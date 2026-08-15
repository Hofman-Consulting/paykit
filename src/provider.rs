//! The [`PaymentProvider`] trait, the crate's central abstraction.

use async_trait::async_trait;

use crate::error::Error;
use crate::money::Money;
use crate::payment::{CreatePayment, Payment, Refund, RefundRequest, VerifiedPayment};

/// Abstraction over a hosted-checkout payment provider (Mollie, Stripe,
/// ...).
///
/// Implementations must be `Send + Sync` and object-safe so they can be
/// shared across an async application as `Arc<dyn PaymentProvider>` — that
/// is the intended injection form.
///
/// # Error contract
///
/// Every method returns [`Error`]. Before retrying a failed call, check
/// [`Error::is_retriable`]. When it returns `false` (e.g. for
/// [`Error::Unauthorized`] or [`Error::InvalidRequest`]), the request
/// itself was rejected and callers **must not** retry it unchanged —
/// retrying cannot succeed and only adds load to a provider that has
/// already said no.
///
/// # Extensibility
///
/// [`cancel_payment`](PaymentProvider::cancel_payment) and
/// [`refund`](PaymentProvider::refund) have default bodies that return
/// [`Error::Unsupported`]. This lets the trait gain new methods in a minor
/// release without breaking existing third-party implementations; a
/// provider that does not implement cancellation or refunds simply inherits
/// the default.
#[async_trait]
pub trait PaymentProvider: Send + Sync {
    /// Creates a new payment with the provider and returns it, typically
    /// including a `checkout_url` the customer should be redirected to.
    async fn create_payment(&self, req: CreatePayment) -> Result<Payment, Error>;

    /// Fetches the current state of a previously created payment.
    async fn get_payment(&self, id: &str) -> Result<Payment, Error>;

    /// Cancels an open payment. Not all providers, or all payment states,
    /// support cancellation.
    ///
    /// The default implementation returns [`Error::Unsupported`].
    async fn cancel_payment(&self, id: &str) -> Result<Payment, Error> {
        let _ = id;
        Err(Error::Unsupported)
    }

    /// Refunds all or part of a paid payment.
    ///
    /// The default implementation returns [`Error::Unsupported`].
    async fn refund(&self, id: &str, req: RefundRequest) -> Result<Refund, Error> {
        let _ = (id, req);
        Err(Error::Unsupported)
    }

    /// Fetches a payment and checks it against `expected` before handing
    /// back a [`VerifiedPayment`].
    ///
    /// # Why this is on the trait
    ///
    /// Every doc in this crate says [`PaymentProvider`] is meant to be
    /// injected as `Arc<dyn PaymentProvider>`. If payment verification were
    /// only available on a concrete provider type, it would be unreachable
    /// the moment an application type-erases behind the trait object, and
    /// callers would fall back to [`get_payment`](Self::get_payment) plus a
    /// hand-rolled amount/status comparison — worse than no helper at all,
    /// since it is easy to get subtly wrong (see below). Putting a
    /// default-bodied `fetch_verified` directly on the trait keeps it
    /// reachable however the provider is held.
    ///
    /// The default implementation calls [`get_payment`](Self::get_payment)
    /// and requires **both**:
    /// - the returned amount and currency exactly match `expected`
    ///   (otherwise [`Error::AmountMismatch`]), and
    /// - the returned status is [`PaymentStatus`](crate::payment::PaymentStatus)`::Paid`
    ///   (otherwise [`Error::NotPaid`]).
    ///
    /// Checking the amount alone is a trap. The obvious use of a "verified"
    /// payment is `if let Ok(v) = fetch_verified(..).await { confirm_order() }`,
    /// and an amount-only check would confirm orders for payments that are
    /// merely open, pending, or authorized — never actually settled. A
    /// [`VerifiedPayment`] must mean "settled *and* the money matches", or
    /// it is not worth the name.
    ///
    /// Implementations with a cheaper or more accurate way to fetch and
    /// check a payment (e.g. a single API call that returns both) may
    /// override this, but any override must preserve both checks.
    ///
    /// # What this does *not* prove
    ///
    /// A verified payment does not prove it belongs to any particular
    /// order — see [`VerifiedPayment`]'s own documentation. Callers must
    /// still look the order up by the payment id *they* stored when they
    /// created the payment, never by a reference or metadata value the
    /// provider echoes back.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AmountMismatch`] if the fetched payment's amount or
    /// currency differs from `expected` (currency comparison is exact).
    /// Returns [`Error::NotPaid`] if the amount matches but the status is
    /// not `Paid`. Also returns any error
    /// [`get_payment`](Self::get_payment) can return.
    async fn fetch_verified(&self, id: &str, expected: Money) -> Result<VerifiedPayment, Error> {
        let payment = self.get_payment(id).await?;
        if payment.amount != expected {
            return Err(Error::AmountMismatch {
                expected,
                actual: payment.amount,
            });
        }
        if !payment.status.is_paid() {
            return Err(Error::not_paid(payment.status));
        }
        Ok(VerifiedPayment::new(payment))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::money::{Currency, Money};
    use crate::payment::PaymentStatus;

    /// Minimal downstream-style provider: implements only the two required
    /// methods, relying on the default `cancel_payment`/`refund` bodies.
    /// This exercises both that the trait is implementable outside this
    /// crate and that it stays object-safe.
    struct FakeProvider;

    #[async_trait]
    impl PaymentProvider for FakeProvider {
        async fn create_payment(&self, req: CreatePayment) -> Result<Payment, Error> {
            Ok(Payment::new("fake_1", PaymentStatus::Open, req.amount()))
        }

        async fn get_payment(&self, id: &str) -> Result<Payment, Error> {
            Ok(Payment::new(
                id,
                PaymentStatus::Open,
                Money::from_minor(0, Currency::EUR),
            ))
        }
    }

    fn provider() -> Arc<dyn PaymentProvider> {
        Arc::new(FakeProvider)
    }

    #[tokio::test]
    async fn arc_dyn_payment_provider_compiles_and_creates_a_payment() {
        let req = CreatePayment::new(
            Money::from_minor(1000, Currency::EUR),
            "order #1",
            "https://shop.example/return",
        );
        let payment = provider().create_payment(req).await.unwrap();
        assert_eq!(payment.status, PaymentStatus::Open);
    }

    #[tokio::test]
    async fn arc_dyn_payment_provider_gets_a_payment() {
        let payment = provider().get_payment("fake_1").await.unwrap();
        assert_eq!(payment.id, "fake_1");
    }

    #[tokio::test]
    async fn default_cancel_payment_is_unsupported_and_not_retriable() {
        let err = provider().cancel_payment("fake_1").await.unwrap_err();
        assert!(matches!(err, Error::Unsupported));
        assert!(!err.is_retriable());
    }

    #[tokio::test]
    async fn default_refund_is_unsupported_and_not_retriable() {
        let err = provider()
            .refund(
                "fake_1",
                RefundRequest::new(Money::from_minor(500, Currency::EUR)),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Unsupported));
        assert!(!err.is_retriable());
    }

    // --- fetch_verified: default implementation, reached through
    // `Arc<dyn PaymentProvider>` to prove the trait stays object-safe. ---

    /// A provider whose `get_payment` always returns a fixed, preset
    /// `Payment`, so `fetch_verified`'s amount/status checks can be
    /// exercised deterministically.
    struct FixedPaymentProvider(Payment);

    #[async_trait]
    impl PaymentProvider for FixedPaymentProvider {
        async fn create_payment(&self, req: CreatePayment) -> Result<Payment, Error> {
            Ok(Payment::new("fixed", PaymentStatus::Open, req.amount()))
        }

        async fn get_payment(&self, _id: &str) -> Result<Payment, Error> {
            Ok(self.0.clone())
        }
    }

    fn fixed_provider(payment: Payment) -> Arc<dyn PaymentProvider> {
        Arc::new(FixedPaymentProvider(payment))
    }

    #[tokio::test]
    async fn fetch_verified_through_arc_dyn_succeeds_when_paid_and_amount_matches() {
        let amount = Money::from_minor(1000, Currency::EUR);
        let provider = fixed_provider(Payment::new("pay_1", PaymentStatus::Paid, amount));

        let verified = provider.fetch_verified("pay_1", amount).await.unwrap();
        assert_eq!(verified.payment().status, PaymentStatus::Paid);
        assert_eq!(verified.payment().amount, amount);
    }

    #[tokio::test]
    async fn fetch_verified_rejects_amount_mismatch() {
        let provider = fixed_provider(Payment::new(
            "pay_1",
            PaymentStatus::Paid,
            Money::from_minor(999, Currency::EUR),
        ));

        let err = provider
            .fetch_verified("pay_1", Money::from_minor(1000, Currency::EUR))
            .await
            .unwrap_err();
        match err {
            Error::AmountMismatch { expected, actual } => {
                assert_eq!(expected, Money::from_minor(1000, Currency::EUR));
                assert_eq!(actual, Money::from_minor(999, Currency::EUR));
            }
            other => panic!("expected AmountMismatch, got {other:?}"),
        }
        assert!(!err.is_retriable());
    }

    #[tokio::test]
    async fn fetch_verified_rejects_matching_amount_that_is_not_yet_paid() {
        // The trap this default implementation exists to close: a matching
        // amount alone must never be treated as "verified".
        let amount = Money::from_minor(1000, Currency::EUR);
        let provider = fixed_provider(Payment::new("pay_1", PaymentStatus::Open, amount));

        let err = provider.fetch_verified("pay_1", amount).await.unwrap_err();
        assert!(!err.is_retriable());
        match err {
            Error::NotPaid { status } => assert_eq!(status, PaymentStatus::Open),
            other => panic!("expected NotPaid, got {other:?}"),
        }
    }
}
