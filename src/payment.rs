//! Payment and refund domain types.

use std::collections::BTreeMap;
use std::fmt;
use std::hash::{BuildHasher, Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::Error;
use crate::money::Money;

/// The state of a payment at the provider.
///
/// This enum is `#[non_exhaustive]`: providers evolve their status sets
/// over time, and this crate maps anything it does not recognize to
/// [`PaymentStatus::Unknown`] rather than failing. Always include a
/// wildcard arm when matching from outside this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum PaymentStatus {
    /// Created, but the customer has not started checkout yet.
    Open,
    /// Checkout is in progress at the provider (e.g. awaiting a bank
    /// transfer or an async payment method).
    Pending,
    /// Funds are reserved but not yet captured.
    Authorized,
    /// Funds have been captured.
    Paid,
    /// The payment failed (e.g. the bank declined it).
    Failed,
    /// The customer or merchant cancelled the payment.
    Cancelled,
    /// The payment expired before the customer completed checkout.
    Expired,
    /// A status this crate version does not recognize.
    ///
    /// # Important
    ///
    /// Treat this as "defer, take no action" — never as a failure or as
    /// grounds to cancel an order. A provider adding a new status must not
    /// be able to make a consumer's `match` fall into a cancellation path;
    /// that would cancel real, possibly-paid orders. Poll again later or
    /// upgrade this crate to get the status mapped properly.
    Unknown(Box<str>),
}

impl PaymentStatus {
    /// Returns `true` if the payment has been paid.
    #[must_use]
    pub fn is_paid(&self) -> bool {
        matches!(self, Self::Paid)
    }

    /// Returns `true` if the payment is in a final state that will not
    /// change on its own.
    ///
    /// [`PaymentStatus::Unknown`] is deliberately **not** terminal — see
    /// its documentation.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Paid | Self::Failed | Self::Cancelled | Self::Expired
        )
    }

    /// Returns a machine-readable name for this status, suitable for
    /// persisting to a database column or an API response: `"open"`,
    /// `"pending"`, `"authorized"`, `"paid"`, `"failed"`, `"cancelled"`,
    /// `"expired"`, or — for [`PaymentStatus::Unknown`] — the raw
    /// provider-supplied value itself (see [`PaymentStatus::raw`]).
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Open => "open",
            Self::Pending => "pending",
            Self::Authorized => "authorized",
            Self::Paid => "paid",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Unknown(raw) => raw,
        }
    }

    /// Returns the raw, provider-supplied status string when this is
    /// [`PaymentStatus::Unknown`], or `None` for every other variant.
    ///
    /// Useful for logging or alerting on a status this crate version does
    /// not yet map, without having to match on the whole enum.
    #[must_use]
    pub fn raw(&self) -> Option<&str> {
        match self {
            Self::Unknown(raw) => Some(raw),
            _ => None,
        }
    }
}

impl fmt::Display for PaymentStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A payment as reported by a provider.
///
/// `#[non_exhaustive]`: this blocks direct struct-literal construction
/// from outside this crate, but **not** construction via [`Payment::new`]
/// together with the `with_*` builder methods below, which remain the
/// supported way for downstream
/// [`PaymentProvider`](crate::provider::PaymentProvider) implementations
/// and test fakes to build one. This lets the crate add a field (e.g. a
/// captured `paid_at` timestamp, payment `method`, or a running
/// `amount_refunded` total) in a minor release without a breaking change.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Payment {
    /// The provider's identifier for this payment.
    pub id: String,
    /// The current status of the payment.
    pub status: PaymentStatus,
    /// The payment amount.
    pub amount: Money,
    /// URL the customer should be redirected to in order to complete
    /// checkout, when applicable (e.g. a freshly created, still-open
    /// payment).
    pub checkout_url: Option<String>,
    /// The caller-supplied reference for this payment, if the provider
    /// echoes it back.
    pub reference: Option<String>,
    /// Provider-specific metadata associated with the payment.
    pub metadata: BTreeMap<String, String>,
}

impl Payment {
    /// Creates a payment with no checkout URL, reference, or metadata set.
    #[must_use]
    pub fn new(id: impl Into<String>, status: PaymentStatus, amount: Money) -> Self {
        Self {
            id: id.into(),
            status,
            amount,
            checkout_url: None,
            reference: None,
            metadata: BTreeMap::new(),
        }
    }

    /// Sets the checkout URL.
    #[must_use]
    pub fn with_checkout_url(mut self, url: impl Into<String>) -> Self {
        self.checkout_url = Some(url.into());
        self
    }

    /// Sets the reference.
    #[must_use]
    pub fn with_reference(mut self, reference: impl Into<String>) -> Self {
        self.reference = Some(reference.into());
        self
    }

    /// Sets the metadata map, replacing any previous value.
    ///
    /// Named `_map` (rather than `with_metadata`, as in an earlier version
    /// of this crate) to distinguish it from
    /// [`CreatePayment::with_metadata_entry`], which inserts a single
    /// key/value pair instead of replacing the whole map — the same name
    /// on both types with different arity and different semantics was a
    /// footgun.
    #[must_use]
    pub fn with_metadata_map(mut self, metadata: BTreeMap<String, String>) -> Self {
        self.metadata = metadata;
        self
    }
}

/// Returns `true` if `url` is an absolute `http://` or `https://` URL.
///
/// Deliberately a plain prefix check rather than a full parse: this crate
/// has no URL-parsing dependency, and a scheme check is enough to catch the
/// realistic mistake (a relative path or a missing scheme) before it turns
/// into a runtime error at the provider.
fn is_absolute_http_url(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

/// Process-wide counter mixed into every generated idempotency key so that
/// two keys generated within the same clock tick still differ. See
/// [`generate_idempotency_key`].
static IDEMPOTENCY_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generates an idempotency key without a UUID (or any other new)
/// dependency, so the core crate can build with `--no-default-features`.
///
/// Not cryptographically random and not a formal uniqueness guarantee —
/// neither is required here. Empirically it is collision-resistant in
/// practice over the window a provider honors an idempotency key for
/// (typically hours), given a working clock and randomness source, which
/// this achieves by hashing together:
/// - the wall-clock time this process generated it, at the best resolution
///   available (nanoseconds since the Unix epoch), when the platform can
///   supply one — see [`now_nanos`];
/// - [`IDEMPOTENCY_COUNTER`], a process-wide monotonically increasing
///   counter, so two keys generated on the same clock tick still differ;
/// - two independent [`std::collections::hash_map::RandomState`] instances
///   as hasher keys, one per hash pass below — each call draws fresh
///   randomness from the OS, the same source `HashMap` uses internally;
/// - `seed`, the caller-supplied request content (amount, description,
///   redirect URL, ...), so two requests that happen to race on the same
///   tick and counter value are still distinguished if their content
///   differs.
///
/// The output is hashed twice, with the first hash's output folded into
/// the second, to widen the result beyond one `u64` worth of entropy.
///
/// This function never panics, including on platforms where the wall clock
/// is unavailable (see [`now_nanos`]): [`CreatePayment::new`] is infallible
/// and non-async, and must not be able to abort the process building it.
fn generate_idempotency_key(seed: impl Hash) -> String {
    use std::collections::hash_map::RandomState;

    let counter = IDEMPOTENCY_COUNTER.fetch_add(1, AtomicOrdering::Relaxed);
    let nanos = now_nanos();

    let mut first = RandomState::new().build_hasher();
    counter.hash(&mut first);
    nanos.hash(&mut first);
    seed.hash(&mut first);
    let a = first.finish();

    let mut second = RandomState::new().build_hasher();
    a.hash(&mut second);
    counter.hash(&mut second);
    let b = second.finish();

    format!("paykit-{a:016x}{b:016x}")
}

/// Returns nanoseconds since the Unix epoch, or `0` if the platform cannot
/// supply a wall clock.
///
/// `std::time::SystemTime::now()` **panics** on targets that fall back to
/// its `unsupported` implementation — notably `wasm32-unknown-unknown`,
/// the target this crate's `--no-default-features` transport-agnostic core
/// is explicitly meant to support. [`generate_idempotency_key`] is reached
/// from the infallible, non-async [`CreatePayment::new`] and
/// [`RefundRequest::new`], so it must never panic; on that target family
/// this returns `0` instead of calling into the panicking implementation,
/// relying on [`IDEMPOTENCY_COUNTER`] and the per-call `RandomState`
/// entropy in [`generate_idempotency_key`] to keep keys distinct.
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
fn now_nanos() -> u128 {
    0
}

/// See the other definition of this function for the full explanation;
/// this is the branch for every target where `SystemTime::now()` is
/// actually implemented.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Request to create a new payment with a provider.
///
/// Fields are private; provider implementations read them through the
/// accessors. Construct with [`CreatePayment::new`] and customize with the
/// fluent `with_*` setters.
///
/// # Equality
///
/// `PartialEq`/`Eq` are hand-written, not derived, and deliberately exclude
/// `idempotency_key`: [`CreatePayment::new`] generates that key randomly,
/// so two structurally identical requests would otherwise never compare
/// equal — a downstream
/// `assert_eq!` on two `CreatePayment`s built the same way would fail with
/// every visible field matching. `Hash` is not derived at all, for the same
/// reason (a `Hash` impl consistent with this `Eq` cannot hash the key
/// either, and this type has no current need to be hashed).
#[derive(Debug, Clone)]
pub struct CreatePayment {
    amount: Money,
    description: String,
    redirect_url: String,
    webhook_url: Option<String>,
    reference: Option<String>,
    idempotency_key: String,
    metadata: BTreeMap<String, String>,
}

impl PartialEq for CreatePayment {
    fn eq(&self, other: &Self) -> bool {
        // `idempotency_key` is intentionally excluded — see the
        // "Equality" section on `CreatePayment`'s own docs.
        self.amount == other.amount
            && self.description == other.description
            && self.redirect_url == other.redirect_url
            && self.webhook_url == other.webhook_url
            && self.reference == other.reference
            && self.metadata == other.metadata
    }
}

impl Eq for CreatePayment {}

impl CreatePayment {
    /// Creates a new payment request.
    ///
    /// `redirect_url` is a required, positional argument (rather than a
    /// builder-settable `Option`) because hosted-checkout providers require
    /// it to complete a payment; a missing redirect URL should be a compile
    /// error here, not a runtime `422` at the provider.
    ///
    /// This constructor never fails, even if `redirect_url` is not an
    /// absolute `http`/`https` URL — it is meant to compose fluently and
    /// its signature cannot return a `Result`. Call [`CreatePayment::validate`]
    /// before sending the request; provider implementations should do so
    /// at the start of `create_payment`.
    ///
    /// # Idempotency
    ///
    /// An idempotency key is generated here, eagerly, and stored — not
    /// generated fresh by the provider on every send. This matters because
    /// [`Error::is_retriable`] tells callers it is safe to retry a failed
    /// `create_payment` call (e.g. after [`Error::Timeout`] or a `5xx`
    /// [`Error::Api`]); if each retry carried a fresh key, that key would
    /// provide no idempotency at all — indistinguishable from sending no
    /// key — and a retried create could produce a second, duplicate live
    /// payment at the provider. Retrying with the *same* `CreatePayment`
    /// value now sends the *same* key every time. Building a genuinely new
    /// request (e.g. re-paying an expired order with a new `CreatePayment`)
    /// gets a fresh key, as it should. Call
    /// [`CreatePayment::with_idempotency_key`] to override the generated
    /// value with one of your own (e.g. derived from your own order id).
    #[must_use]
    pub fn new(
        amount: Money,
        description: impl Into<String>,
        redirect_url: impl Into<String>,
    ) -> Self {
        let description = description.into();
        let redirect_url = redirect_url.into();
        let idempotency_key = generate_idempotency_key((
            amount.minor_units(),
            amount.currency().as_str(),
            description.as_str(),
            redirect_url.as_str(),
        ));
        Self {
            amount,
            description,
            redirect_url,
            webhook_url: None,
            reference: None,
            idempotency_key,
            metadata: BTreeMap::new(),
        }
    }

    /// Sets the webhook URL the provider should call with payment status
    /// updates.
    #[must_use]
    pub fn with_webhook_url(mut self, url: impl Into<String>) -> Self {
        self.webhook_url = Some(url.into());
        self
    }

    /// Sets a caller-defined reference for this payment (e.g. an order
    /// number).
    #[must_use]
    pub fn with_reference(mut self, reference: impl Into<String>) -> Self {
        self.reference = Some(reference.into());
        self
    }

    /// Overrides the idempotency key generated by [`CreatePayment::new`]
    /// with one of your own, so retrying this exact request does not
    /// create a duplicate payment at the provider. See the "Idempotency"
    /// section on [`CreatePayment::new`] for why a key is already present
    /// even if you never call this.
    #[must_use]
    pub fn with_idempotency_key(mut self, key: impl Into<String>) -> Self {
        self.idempotency_key = key.into();
        self
    }

    /// Adds a metadata key/value pair, replacing any previous value for the
    /// same key.
    ///
    /// Named `_entry` (rather than `with_metadata`, as in an earlier
    /// version of this crate) to distinguish it from
    /// [`Payment::with_metadata_map`], which replaces the whole map instead
    /// of inserting one pair — the same name on both types with different
    /// arity and different semantics was a footgun.
    #[must_use]
    pub fn with_metadata_entry(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Validates that `redirect_url`, and `webhook_url` if set, are
    /// absolute `http`/`https` URLs.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidRequest`] naming the offending field if
    /// either URL is not absolute `http`/`https`.
    pub fn validate(&self) -> Result<(), Error> {
        if !is_absolute_http_url(&self.redirect_url) {
            return Err(Error::InvalidRequest(format!(
                "redirect_url must be an absolute http(s) URL, got {:?}",
                self.redirect_url
            )));
        }
        if let Some(url) = &self.webhook_url {
            if !is_absolute_http_url(url) {
                return Err(Error::InvalidRequest(format!(
                    "webhook_url must be an absolute http(s) URL, got {url:?}"
                )));
            }
        }
        Ok(())
    }

    /// Returns the payment amount.
    #[must_use]
    pub fn amount(&self) -> Money {
        self.amount
    }

    /// Returns the payment description.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Returns the redirect URL.
    #[must_use]
    pub fn redirect_url(&self) -> &str {
        &self.redirect_url
    }

    /// Returns the webhook URL, if set.
    #[must_use]
    pub fn webhook_url(&self) -> Option<&str> {
        self.webhook_url.as_deref()
    }

    /// Returns the reference, if set.
    #[must_use]
    pub fn reference(&self) -> Option<&str> {
        self.reference.as_deref()
    }

    /// Returns the idempotency key: either the one generated by
    /// [`CreatePayment::new`], or the one supplied via
    /// [`CreatePayment::with_idempotency_key`]. Always present — see the
    /// "Idempotency" section on [`CreatePayment::new`].
    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    /// Returns the metadata map.
    #[must_use]
    pub fn metadata(&self) -> &BTreeMap<String, String> {
        &self.metadata
    }
}

/// Request to refund all or part of a paid payment.
///
/// Fields are private; provider implementations read them through the
/// accessors. Construct with [`RefundRequest::new`] and customize with the
/// fluent `with_*` setters.
///
/// # Full refunds
///
/// There is no way to omit the amount for "a full refund": Mollie's
/// `POST /v2/payments/{id}/refunds` declares `amount` a required field —
/// its own `422` response for a missing one is literally "The 'amount'
/// field is missing" — so a request that omits it always fails in
/// production. To issue a full refund, pass the payment's own amount
/// explicitly (e.g. from the [`Payment`] returned by
/// [`PaymentProvider::get_payment`](crate::provider::PaymentProvider::get_payment));
/// the caller is responsible for knowing it.
///
/// # Idempotency
///
/// Like [`CreatePayment`], an idempotency key is generated eagerly by
/// [`RefundRequest::new`] and stored, not left for the provider
/// implementation to generate fresh on every send.
/// [`PaymentProvider::refund`](crate::provider::PaymentProvider::refund)
/// follows the same retry contract as `create_payment`
/// ([`Error::is_retriable`](crate::error::Error::is_retriable) is `true`
/// for [`Error::Timeout`] and a `5xx`), so a key generated fresh on every
/// retry would provide no protection at all — and unlike a duplicate
/// payment, a duplicate refund loses money directly. Call
/// [`RefundRequest::with_idempotency_key`] to override the generated value
/// with one of your own.
///
/// # Equality
///
/// `PartialEq`/`Eq` are hand-written, not derived, and exclude
/// `idempotency_key` for the same reason as [`CreatePayment`]: the key is
/// random, so two structurally identical requests must still compare equal.
#[derive(Debug, Clone)]
pub struct RefundRequest {
    amount: Money,
    description: Option<String>,
    idempotency_key: String,
}

impl PartialEq for RefundRequest {
    fn eq(&self, other: &Self) -> bool {
        // `idempotency_key` is intentionally excluded — see the
        // "Equality" section on `RefundRequest`'s own docs.
        self.amount == other.amount && self.description == other.description
    }
}

impl Eq for RefundRequest {}

impl RefundRequest {
    /// Creates a refund request for `amount`, with no description set and a
    /// freshly generated idempotency key. See the "Full refunds" section on
    /// [`RefundRequest`] for what to pass to refund a payment in full, and
    /// the "Idempotency" section for why a key is already present even if
    /// you never call [`RefundRequest::with_idempotency_key`].
    #[must_use]
    pub fn new(amount: Money) -> Self {
        let idempotency_key =
            generate_idempotency_key((amount.minor_units(), amount.currency().as_str()));
        Self {
            amount,
            description: None,
            idempotency_key,
        }
    }

    /// Sets a caller-defined description for the refund.
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Overrides the idempotency key generated by [`RefundRequest::new`]
    /// with one of your own, so retrying this exact request does not
    /// create a duplicate refund at the provider.
    #[must_use]
    pub fn with_idempotency_key(mut self, key: impl Into<String>) -> Self {
        self.idempotency_key = key.into();
        self
    }

    /// Returns the refund amount.
    #[must_use]
    pub fn amount(&self) -> Money {
        self.amount
    }

    /// Returns the description, if set.
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Returns the idempotency key: either the one generated by
    /// [`RefundRequest::new`], or the one supplied via
    /// [`RefundRequest::with_idempotency_key`]. Always present — see the
    /// "Idempotency" section on [`RefundRequest`].
    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }
}

/// The state of a refund at the provider.
///
/// `#[non_exhaustive]` for the same reason as [`PaymentStatus`]: always
/// include a wildcard arm when matching from outside this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum RefundStatus {
    /// Accepted by the provider but not yet being processed.
    Queued,
    /// Awaiting processing.
    Pending,
    /// Being processed by the provider or the customer's bank.
    Processing,
    /// Completed.
    Refunded,
    /// Failed.
    Failed,
    /// A status this crate version does not recognize. See
    /// [`PaymentStatus::Unknown`] for the same caveat: do not treat this as
    /// a failure.
    Unknown(Box<str>),
}

impl RefundStatus {
    /// Returns a machine-readable name for this status, suitable for
    /// persisting to a database column or an API response: `"queued"`,
    /// `"pending"`, `"processing"`, `"refunded"`, `"failed"`, or — for
    /// [`RefundStatus::Unknown`] — the raw provider-supplied value itself
    /// (see [`RefundStatus::raw`]).
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Queued => "queued",
            Self::Pending => "pending",
            Self::Processing => "processing",
            Self::Refunded => "refunded",
            Self::Failed => "failed",
            Self::Unknown(raw) => raw,
        }
    }

    /// Returns the raw, provider-supplied status string when this is
    /// [`RefundStatus::Unknown`], or `None` for every other variant.
    #[must_use]
    pub fn raw(&self) -> Option<&str> {
        match self {
            Self::Unknown(raw) => Some(raw),
            _ => None,
        }
    }
}

impl fmt::Display for RefundStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A refund as reported by a provider.
///
/// `#[non_exhaustive]`: this blocks direct struct-literal construction
/// from outside this crate, but not construction via [`Refund::new`],
/// which downstream [`PaymentProvider`](crate::provider::PaymentProvider)
/// implementations and test fakes should use instead. This lets the crate
/// add a field in a minor release without a breaking change.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Refund {
    /// The provider's identifier for this refund.
    pub id: String,
    /// The provider's identifier for the payment being refunded.
    pub payment_id: String,
    /// The refunded amount.
    pub amount: Money,
    /// The current status of the refund.
    pub status: RefundStatus,
}

impl Refund {
    /// Creates a refund.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        payment_id: impl Into<String>,
        amount: Money,
        status: RefundStatus,
    ) -> Self {
        Self {
            id: id.into(),
            payment_id: payment_id.into(),
            amount,
            status,
        }
    }
}

/// A [`Payment`] whose amount and settlement status have been checked
/// against a caller-supplied expected value.
///
/// The only way to obtain one is
/// [`PaymentProvider::fetch_verified`](crate::provider::PaymentProvider::fetch_verified)
/// — there is deliberately no public constructor, `Default` impl, `From`
/// impl, `Deserialize` impl, or way to get a `&mut Payment` out of one.
/// This type's entire value as a security control is that *holding one is
/// the proof*: it cannot be forged or reconstructed from a plain
/// [`Payment`], only produced by an actual verifying call to a provider.
///
/// # What this does and does not prove
///
/// Holding a `VerifiedPayment` proves that, as of the verifying call, the
/// provider reported this payment as **settled**
/// ([`PaymentStatus::Paid`]) **and** for the exact amount the caller
/// expected. It does *not* prove the payment belongs to any particular
/// order: callers must still look the order up by the payment id *they*
/// stored when they created the payment, never by a reference or metadata
/// value the provider echoes back — anyone triggering their own unrelated
/// payment at the same provider could set those to anything.
#[derive(Debug)]
pub struct VerifiedPayment {
    payment: Payment,
}

impl VerifiedPayment {
    /// Wraps `payment` as verified.
    ///
    /// Deliberately `pub(crate)`, never `pub`: this must only be reachable
    /// from an actual verifying call within this crate (specifically
    /// [`PaymentProvider::fetch_verified`](crate::provider::PaymentProvider::fetch_verified)'s
    /// default implementation), never called directly by a consumer or a
    /// downstream `PaymentProvider` implementation with an unchecked
    /// `Payment`.
    pub(crate) fn new(payment: Payment) -> Self {
        Self { payment }
    }

    /// Returns the verified payment.
    #[must_use]
    pub fn payment(&self) -> &Payment {
        &self.payment
    }

    /// Consumes this wrapper, returning the verified payment.
    #[must_use]
    pub fn into_payment(self) -> Payment {
        self.payment
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::money::Currency;

    fn amount() -> Money {
        Money::from_minor(1000, Currency::EUR)
    }

    // --- PaymentStatus ---

    #[test]
    fn only_paid_is_paid() {
        assert!(PaymentStatus::Paid.is_paid());
        for status in [
            PaymentStatus::Open,
            PaymentStatus::Pending,
            PaymentStatus::Authorized,
            PaymentStatus::Failed,
            PaymentStatus::Cancelled,
            PaymentStatus::Expired,
            PaymentStatus::Unknown("weird".into()),
        ] {
            assert!(!status.is_paid(), "{status:?} should not be paid");
        }
    }

    #[test]
    fn terminal_statuses() {
        for status in [
            PaymentStatus::Paid,
            PaymentStatus::Failed,
            PaymentStatus::Cancelled,
            PaymentStatus::Expired,
        ] {
            assert!(status.is_terminal(), "{status:?} should be terminal");
        }
        for status in [
            PaymentStatus::Open,
            PaymentStatus::Pending,
            PaymentStatus::Authorized,
        ] {
            assert!(!status.is_terminal(), "{status:?} should not be terminal");
        }
    }

    #[test]
    fn unknown_status_is_not_terminal() {
        assert!(!PaymentStatus::Unknown("future_status".into()).is_terminal());
    }

    // --- Payment ---

    #[test]
    fn payment_new_has_no_optional_fields_set() {
        let payment = Payment::new("pay_1", PaymentStatus::Open, amount());
        assert_eq!(payment.id, "pay_1");
        assert_eq!(payment.status, PaymentStatus::Open);
        assert_eq!(payment.amount, amount());
        assert_eq!(payment.checkout_url, None);
        assert_eq!(payment.reference, None);
        assert!(payment.metadata.is_empty());
    }

    #[test]
    fn payment_builder_methods_set_fields() {
        let mut metadata = BTreeMap::new();
        metadata.insert("order_id".to_string(), "42".to_string());

        let payment = Payment::new("pay_1", PaymentStatus::Paid, amount())
            .with_checkout_url("https://provider.example/checkout/pay_1")
            .with_reference("order-42")
            .with_metadata_map(metadata.clone());

        assert_eq!(
            payment.checkout_url.as_deref(),
            Some("https://provider.example/checkout/pay_1")
        );
        assert_eq!(payment.reference.as_deref(), Some("order-42"));
        assert_eq!(payment.metadata, metadata);
    }

    // --- generate_idempotency_key / now_nanos ---

    #[test]
    fn generate_idempotency_key_never_panics_across_many_calls() {
        // Regression coverage for the host platform: whatever the clock
        // and randomness sources do, this must never panic.
        //
        // The bug this is guarding against — `SystemTime::now()` panicking
        // on `wasm32-unknown-unknown`, which has no clock implementation —
        // can only be *observed* at runtime on that target. This crate's
        // dev-dependencies (`tokio`'s `rt-multi-thread`, via `mio`) do not
        // build for `wasm32-unknown-unknown`, so the unit test binary
        // cannot be built for it here, and this repository's CI does not
        // target wasm at all. What *is* verified in this environment:
        // `cargo check --target wasm32-unknown-unknown --no-default-features`
        // compiles cleanly, which selects `now_nanos`'s
        // `#[cfg(all(target_family = "wasm", target_os = "unknown"))]`
        // branch — the one that returns `0` instead of calling
        // `SystemTime::now()` — for that target.
        for i in 0..1000 {
            let key = generate_idempotency_key(i);
            assert!(!key.is_empty());
        }
    }

    // --- CreatePayment ---

    #[test]
    fn create_payment_new_sets_required_fields() {
        let req = CreatePayment::new(amount(), "order #42", "https://shop.example/return");
        assert_eq!(req.amount(), amount());
        assert_eq!(req.description(), "order #42");
        assert_eq!(req.redirect_url(), "https://shop.example/return");
        assert_eq!(req.webhook_url(), None);
        assert_eq!(req.reference(), None);
        assert!(req.metadata().is_empty());
    }

    #[test]
    fn create_payment_new_generates_a_non_empty_idempotency_key() {
        let req = CreatePayment::new(amount(), "order #42", "https://shop.example/return");
        assert!(!req.idempotency_key().is_empty());
    }

    #[test]
    fn create_payment_new_generates_different_keys_for_different_requests() {
        let a = CreatePayment::new(amount(), "order #1", "https://shop.example/return");
        let b = CreatePayment::new(amount(), "order #2", "https://shop.example/return");
        assert_ne!(a.idempotency_key(), b.idempotency_key());
    }

    #[test]
    fn create_payment_new_generates_different_keys_across_calls_with_identical_content() {
        // Same amount/description/redirect_url each time — only the clock
        // tick, process-random seed, and counter can distinguish these.
        let a = CreatePayment::new(amount(), "order", "https://shop.example/return");
        let b = CreatePayment::new(amount(), "order", "https://shop.example/return");
        assert_ne!(a.idempotency_key(), b.idempotency_key());
    }

    #[test]
    fn create_payment_builder_methods_set_fields() {
        let req = CreatePayment::new(amount(), "order #42", "https://shop.example/return")
            .with_webhook_url("https://shop.example/webhooks/payment")
            .with_reference("order-42")
            .with_idempotency_key("idem-1")
            .with_metadata_entry("order_id", "42")
            .with_metadata_entry("channel", "web");

        assert_eq!(
            req.webhook_url(),
            Some("https://shop.example/webhooks/payment")
        );
        assert_eq!(req.reference(), Some("order-42"));
        assert_eq!(req.idempotency_key(), "idem-1");
        assert_eq!(
            req.metadata().get("order_id").map(String::as_str),
            Some("42")
        );
        assert_eq!(
            req.metadata().get("channel").map(String::as_str),
            Some("web")
        );
    }

    #[test]
    fn create_payment_equality_ignores_the_generated_idempotency_key() {
        // Two structurally identical requests carry different, randomly
        // generated idempotency keys (see `generate_idempotency_key`), but
        // must still compare equal on every field a caller can observe —
        // otherwise a downstream `assert_eq!(create_payment_a, create_payment_b)`
        // fails on every visible field matching, which is misleading.
        let a = CreatePayment::new(amount(), "order #42", "https://shop.example/return");
        let b = CreatePayment::new(amount(), "order #42", "https://shop.example/return");
        assert_ne!(a.idempotency_key(), b.idempotency_key());
        assert_eq!(a, b);
    }

    #[test]
    fn create_payment_equality_still_distinguishes_other_fields() {
        let a = CreatePayment::new(amount(), "order #1", "https://shop.example/return");
        let b = CreatePayment::new(amount(), "order #2", "https://shop.example/return");
        assert_ne!(a, b);
    }

    #[test]
    fn create_payment_with_idempotency_key_overrides_the_generated_one() {
        let req = CreatePayment::new(amount(), "order", "https://shop.example/return")
            .with_idempotency_key("caller-chosen");
        assert_eq!(req.idempotency_key(), "caller-chosen");
    }

    #[test]
    fn create_payment_metadata_overwrites_same_key() {
        let req = CreatePayment::new(amount(), "d", "https://shop.example/return")
            .with_metadata_entry("k", "first")
            .with_metadata_entry("k", "second");
        assert_eq!(req.metadata().len(), 1);
        assert_eq!(req.metadata().get("k").map(String::as_str), Some("second"));
    }

    #[test]
    fn validate_accepts_absolute_https_urls() {
        let req = CreatePayment::new(amount(), "d", "https://shop.example/return")
            .with_webhook_url("https://shop.example/webhooks/payment");
        assert!(req.validate().is_ok());
    }

    #[test]
    fn validate_accepts_absolute_http_urls() {
        let req = CreatePayment::new(amount(), "d", "http://shop.example/return");
        assert!(req.validate().is_ok());
    }

    #[test]
    fn validate_rejects_relative_redirect_url() {
        let req = CreatePayment::new(amount(), "d", "/return");
        let err = req.validate().unwrap_err();
        assert!(matches!(err, Error::InvalidRequest(_)));
        assert!(!err.is_retriable());
    }

    #[test]
    fn validate_rejects_non_http_scheme_redirect_url() {
        let req = CreatePayment::new(amount(), "d", "ftp://shop.example/return");
        assert!(req.validate().is_err());
    }

    #[test]
    fn validate_rejects_relative_webhook_url_even_with_valid_redirect_url() {
        let req = CreatePayment::new(amount(), "d", "https://shop.example/return")
            .with_webhook_url("/webhooks/payment");
        assert!(req.validate().is_err());
    }

    // --- RefundRequest ---

    #[test]
    fn refund_request_new_requires_an_amount_and_sets_nothing_else() {
        let req = RefundRequest::new(amount());
        assert_eq!(req.amount(), amount());
        assert_eq!(req.description(), None);
    }

    #[test]
    fn refund_request_new_generates_a_non_empty_idempotency_key() {
        // Following this crate's own retry protocol (`Error::is_retriable`
        // is `true` for `Error::Timeout` and a 5xx from `refund`) must not
        // issue a second refund, exactly as for `CreatePayment::new` — see
        // its "Idempotency" doc section.
        let req = RefundRequest::new(amount());
        assert!(!req.idempotency_key().is_empty());
    }

    #[test]
    fn refund_request_new_generates_different_keys_across_calls_with_identical_content() {
        let a = RefundRequest::new(amount());
        let b = RefundRequest::new(amount());
        assert_ne!(a.idempotency_key(), b.idempotency_key());
    }

    #[test]
    fn refund_request_builder_methods_set_fields() {
        let req = RefundRequest::new(amount())
            .with_description("customer requested")
            .with_idempotency_key("idem-refund-1");
        assert_eq!(req.amount(), amount());
        assert_eq!(req.description(), Some("customer requested"));
        assert_eq!(req.idempotency_key(), "idem-refund-1");
    }

    #[test]
    fn refund_request_equality_ignores_the_generated_idempotency_key() {
        let a = RefundRequest::new(amount());
        let b = RefundRequest::new(amount());
        assert_ne!(a.idempotency_key(), b.idempotency_key());
        assert_eq!(a, b);
    }

    #[test]
    fn refund_request_equality_still_distinguishes_other_fields() {
        let a = RefundRequest::new(amount()).with_description("a");
        let b = RefundRequest::new(amount()).with_description("b");
        assert_ne!(a, b);
    }

    // --- Refund / RefundStatus ---

    #[test]
    fn refund_new_sets_all_fields() {
        let refund = Refund::new("re_1", "pay_1", amount(), RefundStatus::Refunded);
        assert_eq!(refund.id, "re_1");
        assert_eq!(refund.payment_id, "pay_1");
        assert_eq!(refund.amount, amount());
        assert_eq!(refund.status, RefundStatus::Refunded);
    }

    #[test]
    fn refund_status_unknown_carries_the_raw_value() {
        let status = RefundStatus::Unknown("future_status".into());
        assert_eq!(status, RefundStatus::Unknown("future_status".into()));
    }

    #[test]
    fn refund_status_as_str_and_display() {
        assert_eq!(RefundStatus::Refunded.as_str(), "refunded");
        assert_eq!(RefundStatus::Refunded.to_string(), "refunded");
        assert_eq!(
            RefundStatus::Unknown("future_status".into()).as_str(),
            "future_status"
        );
    }

    #[test]
    fn refund_status_raw_is_only_some_for_unknown() {
        assert_eq!(RefundStatus::Refunded.raw(), None);
        assert_eq!(
            RefundStatus::Unknown("future_status".into()).raw(),
            Some("future_status")
        );
    }

    // --- PaymentStatus::as_str / Display / raw ---

    #[test]
    fn payment_status_as_str_and_display() {
        assert_eq!(PaymentStatus::Paid.as_str(), "paid");
        assert_eq!(PaymentStatus::Paid.to_string(), "paid");
        assert_eq!(
            PaymentStatus::Unknown("future_status".into()).as_str(),
            "future_status"
        );
    }

    #[test]
    fn payment_status_raw_is_only_some_for_unknown() {
        assert_eq!(PaymentStatus::Paid.raw(), None);
        assert_eq!(
            PaymentStatus::Unknown("future_status".into()).raw(),
            Some("future_status")
        );
    }

    // --- VerifiedPayment ---

    #[test]
    fn verified_payment_exposes_the_wrapped_payment_by_reference_and_by_value() {
        let payment = Payment::new("pay_1", PaymentStatus::Paid, amount());
        let verified = VerifiedPayment::new(payment.clone());
        assert_eq!(verified.payment(), &payment);
        assert_eq!(verified.into_payment(), payment);
    }

    // --- serde (gated behind the `serde` feature) ---
    //
    // `serde_json` is an unconditional dev-dependency, so these tests only
    // need `paykit`'s own `serde` feature enabled, not any change to
    // dev-dependencies.

    #[test]
    #[cfg(feature = "serde")]
    fn payment_serde_round_trip() {
        let mut metadata = BTreeMap::new();
        metadata.insert("order_id".to_string(), "42".to_string());

        let payment = Payment::new("pay_1", PaymentStatus::Paid, amount())
            .with_checkout_url("https://provider.example/checkout/pay_1")
            .with_reference("order-42")
            .with_metadata_map(metadata);

        let json = serde_json::to_string(&payment).unwrap();
        let back: Payment = serde_json::from_str(&json).unwrap();
        assert_eq!(back, payment);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn refund_serde_round_trip() {
        let refund = Refund::new("re_1", "pay_1", amount(), RefundStatus::Refunded);
        let json = serde_json::to_string(&refund).unwrap();
        let back: Refund = serde_json::from_str(&json).unwrap();
        assert_eq!(back, refund);
    }

    // `PaymentStatus::Unknown(Box<str>)` is the crate's escape hatch for a
    // provider status this version does not recognize (see its doc
    // comment). Its externally-tagged shape — `{"Unknown":"<raw value>"}`,
    // serde's default for a single-field newtype variant — becomes a
    // de-facto persistence format the moment anyone enables `serde` and
    // stores a `Payment`. Pin it explicitly so a future serde-derive
    // attribute change (e.g. adding `#[serde(tag = ...)]`) cannot silently
    // change that format out from under a consumer's stored data.
    #[test]
    #[cfg(feature = "serde")]
    fn payment_status_unknown_has_the_expected_external_tag_shape() {
        let status = PaymentStatus::Unknown("future_status".into());
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "{\"Unknown\":\"future_status\"}");

        let back: PaymentStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, status);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn payment_status_known_variant_serializes_as_a_bare_string() {
        // Contrast with `Unknown`'s object shape above: a unit variant with
        // no payload serializes as a plain JSON string.
        let json = serde_json::to_string(&PaymentStatus::Paid).unwrap();
        assert_eq!(json, "\"Paid\"");
    }

    #[test]
    #[cfg(feature = "serde")]
    fn refund_status_unknown_has_the_expected_external_tag_shape() {
        // Same persistence-format concern as `PaymentStatus::Unknown`
        // above, and the same shape.
        let status = RefundStatus::Unknown("future_status".into());
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "{\"Unknown\":\"future_status\"}");

        let back: RefundStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, status);
    }
}
