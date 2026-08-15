//! Helpers for handling Mollie's payment webhook.
//!
//! Mollie does not sign webhook deliveries. Its webhook endpoint is a bare notification —
//! "something changed about payment `tr_xxx`, go look" — sent as an unauthenticated
//! `POST` with an `application/x-www-form-urlencoded` body containing a single `id` field.
//! Anyone can `POST` anything to your webhook URL; nothing in the request itself proves it
//! came from Mollie or reflects a real payment.
//!
//! Everything in this module exists to get the payment id out of that untrusted body
//! *cheaply* before you spend an outbound, authenticated API call re-fetching the real
//! state. Nothing here is, or is a substitute for, verification.
//!
//! # Security
//!
//! The only correct way to handle a Mollie webhook delivery is:
//!
//! 1. Read the raw request body and pass it to [`parse_webhook_body`] (or call
//!    [`is_valid_payment_id`] yourself if you have already extracted the `id` field some
//!    other way). This is a *format* check — it rejects obviously-malformed input (wrong
//!    prefix, empty, oversized, non-alphanumeric) so you do not spend an HTTP request
//!    finding that out from Mollie instead. It says nothing about whether the id refers to
//!    a real payment, let alone one of yours.
//! 2. Re-fetch the payment from the Mollie API — never trust the amount, status, or
//!    metadata in the webhook body itself, only the id — supplying the amount you expect
//!    for the order you believe this payment is for. In this crate that is
//!    [`PaymentProvider::fetch_verified`](crate::PaymentProvider::fetch_verified), which
//!    checks two things before handing back a [`VerifiedPayment`](crate::VerifiedPayment):
//!    the amount and currency Mollie reports must match the one you pass in — failing with
//!    [`crate::Error::AmountMismatch`] on any mismatch (underpayment, overpayment, or wrong
//!    currency) — and the payment's status must be paid — failing with
//!    [`crate::Error::NotPaid`] otherwise. Either check failing means there is no
//!    `VerifiedPayment` to obtain; you never have to remember to compare the amount or the
//!    status yourself.
//! 3. Look your order up **by the payment id you stored yourself** when you created the
//!    payment — never by a reference, description, or metadata field echoed back in the
//!    webhook body or in the re-fetched payment. Those values round-trip through Mollie,
//!    and some of them originate from input a customer can influence.
//! 4. Treat any status this crate does not recognise
//!    ([`PaymentStatus::Unknown`](crate::PaymentStatus::Unknown)) as "defer, take no
//!    action" — never as a failure and never as grounds to cancel the order. Mollie adding
//!    a new status must not be able to make your webhook handler cancel a real, possibly
//!    already-paid order.
//!
//! See the crate-level docs and `SECURITY.md` for the full integrator checklist (row-locked
//! forward-only status transitions, webhook response codes, reconciliation, rate limiting).

/// Returns `true` if `id` has the shape of a Mollie payment id: the literal prefix `tr_`
/// followed by 1 to 60 ASCII alphanumeric characters.
///
/// # Not an authenticity check
///
/// This is a **cheap format and denial-of-service filter**, not a verification of
/// anything. It exists solely to reject obviously-malformed input — the wrong prefix, an
/// empty or absurdly long suffix, or characters that have no business in an id — before an
/// outbound HTTP request is spent finding that out from the Mollie API.
///
/// Passing this check proves nothing about whether `id` refers to a payment that exists,
/// let alone one that belongs to you, was actually paid, or was paid the right amount.
/// Mollie does not sign its webhook deliveries, so there is no cryptographic authenticity
/// check available at this layer at all. The actual control is re-fetching the payment
/// from the Mollie API and comparing the amount it reports against your own stored order
/// total — see the module-level `# Security` section.
///
/// # Examples
///
/// ```
/// use paykit::providers::mollie::webhook::is_valid_payment_id;
///
/// assert!(is_valid_payment_id("tr_WDqYK6vllg"));
/// assert!(!is_valid_payment_id("not-a-payment-id"));
/// ```
#[must_use]
pub fn is_valid_payment_id(id: &str) -> bool {
    match id.strip_prefix("tr_") {
        Some(rest) => {
            !rest.is_empty() && rest.len() <= 60 && rest.chars().all(|c| c.is_ascii_alphanumeric())
        }
        None => false,
    }
}

/// Extracts and format-validates the `id` field from a Mollie webhook body.
///
/// Mollie posts `application/x-www-form-urlencoded` with a single field, `id=tr_xxx`.
/// This parser looks for an `id` key among `&`-separated `key=value` pairs — field order
/// and the presence of other fields do not matter, and if `id` appears more than once the
/// first occurrence wins.
///
/// Returns `None` if no `id` field is present, if it has no value, or if the value does
/// not pass [`is_valid_payment_id`].
///
/// # Caller must bound the input length
///
/// This function does not itself limit the size of `body`. Bounding the size of an
/// untrusted request body is an HTTP-layer concern (see the endpoint-hardening advice in
/// `SECURITY.md`) and has to happen before the body reaches here — by the time a `&str`
/// exists to pass in, an unbounded read has already happened. Do not call this on an
/// unbounded read of the request body.
///
/// # No percent-decoding
///
/// This parser is deliberately dependency-free and does not decode percent-encoding. That
/// is a deliberate strictness choice, not an oversight: `id` (the key) and every character
/// [`is_valid_payment_id`] accepts in the value are all in the URL-encoding "unreserved"
/// set, so a conformant encoder never percent-encodes either of them. A body where `id` is
/// spelled `%69%64`, or whose value contains a `%`, is not a well-formed Mollie webhook
/// delivery by this parser's stricter standard, even though a spec-compliant percent-decoder
/// would accept it (decoding `%69%64` to `id` and reading the value through). Rejecting it
/// here — rather than matching what a general-purpose decoder would eventually do — closes
/// off parameter smuggling between this parser and any other parser that might see the same
/// body (e.g. a framework's own form-decoding middleware, or a proxy in front of it) and
/// disagree with it about what `id` means.
///
/// # Examples
///
/// ```
/// use paykit::providers::mollie::webhook::parse_webhook_body;
///
/// assert_eq!(parse_webhook_body("id=tr_WDqYK6vllg"), Some("tr_WDqYK6vllg"));
/// assert_eq!(parse_webhook_body("foo=bar"), None);
/// ```
#[must_use]
pub fn parse_webhook_body(body: &str) -> Option<&str> {
    for pair in body.split('&') {
        let mut kv = pair.splitn(2, '=');
        let key = kv.next().unwrap_or("");
        let Some(value) = kv.next() else {
            continue;
        };
        if key == "id" {
            return is_valid_payment_id(value).then_some(value);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- is_valid_payment_id ---

    #[test]
    fn valid_id_passes() {
        assert!(is_valid_payment_id("tr_WDqYK6vllg"));
        assert!(is_valid_payment_id("tr_7UhSN1zuXS"));
        assert!(is_valid_payment_id("tr_1"));
    }

    #[test]
    fn missing_prefix_fails() {
        assert!(!is_valid_payment_id("WDqYK6vllg"));
        assert!(!is_valid_payment_id("pay_WDqYK6vllg"));
    }

    #[test]
    fn empty_suffix_fails() {
        assert!(!is_valid_payment_id("tr_"));
    }

    #[test]
    fn non_alphanumeric_suffix_fails() {
        assert!(!is_valid_payment_id("tr_abc-123"));
        assert!(!is_valid_payment_id("tr_abc 123"));
        assert!(!is_valid_payment_id("tr_abc_123"));
    }

    #[test]
    fn sixty_one_char_suffix_fails() {
        let id = format!("tr_{}", "a".repeat(61));
        assert!(!is_valid_payment_id(&id));
    }

    #[test]
    fn sixty_char_suffix_passes() {
        let id = format!("tr_{}", "a".repeat(60));
        assert!(is_valid_payment_id(&id));
    }

    #[test]
    fn empty_string_fails() {
        assert!(!is_valid_payment_id(""));
    }

    #[test]
    fn sql_injection_attempt_fails() {
        assert!(!is_valid_payment_id("tr_'; DROP TABLE orders; --"));
    }

    // --- parse_webhook_body ---

    #[test]
    fn parses_bare_id_field() {
        assert_eq!(
            parse_webhook_body("id=tr_WDqYK6vllg"),
            Some("tr_WDqYK6vllg")
        );
    }

    #[test]
    fn parses_id_field_with_trailing_extra_field() {
        assert_eq!(
            parse_webhook_body("id=tr_WDqYK6vllg&foo=bar"),
            Some("tr_WDqYK6vllg")
        );
    }

    #[test]
    fn parses_id_field_with_leading_extra_field() {
        assert_eq!(
            parse_webhook_body("foo=bar&id=tr_WDqYK6vllg"),
            Some("tr_WDqYK6vllg")
        );
    }

    #[test]
    fn parses_id_field_surrounded_by_extra_fields() {
        assert_eq!(
            parse_webhook_body("a=1&id=tr_WDqYK6vllg&b=2"),
            Some("tr_WDqYK6vllg")
        );
    }

    #[test]
    fn first_id_field_wins_on_duplicates() {
        let first = format!("tr_{}", "a".repeat(10));
        let second = format!("tr_{}", "b".repeat(10));
        let body = format!("id={first}&id={second}");
        assert_eq!(parse_webhook_body(&body), Some(first.as_str()));
    }

    #[test]
    fn missing_id_field_returns_none() {
        assert_eq!(parse_webhook_body("foo=bar&baz=qux"), None);
    }

    #[test]
    fn empty_body_returns_none() {
        assert_eq!(parse_webhook_body(""), None);
    }

    #[test]
    fn id_field_with_no_value_returns_none() {
        assert_eq!(parse_webhook_body("id&foo=bar"), None);
        assert_eq!(parse_webhook_body("id="), None);
    }

    #[test]
    fn malformed_id_value_returns_none() {
        assert_eq!(parse_webhook_body("id=tr_abc-123"), None);
        assert_eq!(parse_webhook_body("id=not-a-payment-id"), None);
    }

    #[test]
    fn percent_encoded_id_value_is_rejected_not_decoded() {
        // A conformant encoder never percent-encodes an alphanumeric `tr_...` id; a body
        // that does is not well-formed, and the parser fails closed rather than decoding.
        assert_eq!(parse_webhook_body("id=tr_ABC%31"), None);
    }

    #[test]
    fn percent_encoded_id_key_is_not_recognized() {
        assert_eq!(parse_webhook_body("%69%64=tr_WDqYK6vllg"), None);
    }

    #[test]
    fn sql_injection_attempt_in_body_returns_none() {
        assert_eq!(parse_webhook_body("id=tr_'; DROP TABLE orders; --"), None);
    }
}
