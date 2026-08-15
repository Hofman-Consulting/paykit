//! Error types returned by [`PaymentProvider`](crate::provider::PaymentProvider)
//! implementations.

use std::time::Duration;

use thiserror::Error;

use crate::money::Money;
use crate::payment::PaymentStatus;

/// Errors that can occur when interacting with a payment provider.
///
/// This enum is `#[non_exhaustive]`: new variants may be added in a minor
/// release. Always include a wildcard arm (`_ => ...`) when matching on it
/// from outside this crate.
///
/// # Retrying
///
/// Call [`Error::is_retriable`] before retrying a failed call. Some errors
/// (e.g. [`Error::Unauthorized`] or [`Error::InvalidRequest`]) mean the
/// request itself is wrong and retrying it will never succeed — doing so
/// anyway just hammers the provider with a request it has already rejected.
///
/// # Security
///
/// The rule is: **no provider-supplied text appears in `Display` or
/// `Debug`.** [`Error::Api`], [`Error::Decode`], [`Error::NotFound`], and
/// [`Error::Unauthorized`] may carry the raw response body the provider
/// sent, for debugging, and [`Error::Api`] additionally carries `title` and
/// `detail`. All of this is free-form text the provider (or a compromised
/// or misconfigured proxy in front of one) chose, and it can contain
/// sensitive data — card details, customer PII, or an echoed
/// `Authorization` header are all realistic, not just hypothetical. None of
/// it is treated as safe by default, regardless of which field it landed
/// in: `title` is not somehow more trustworthy than `detail` just because
/// it is required rather than optional. Retrieve it explicitly via
/// [`Error::raw_body`], [`Error::title`], or [`Error::detail`] only when
/// you know it is safe to log or expose in your context.
///
/// This redaction covers `Display` and `Debug` only. [`Error::Transport`]
/// keeps `#[source]` on its inner error deliberately — it is genuinely
/// useful for error-chain walkers (`anyhow`'s `{:#}`,
/// [`std::error::Report`], `tracing`) — so `source()` is transparent by
/// design, not redacted. A [`PaymentProvider`](crate::provider::PaymentProvider)
/// implementation that constructs [`Error::Transport`] must therefore not
/// put a secret in the inner error it wraps.
#[derive(Error)]
#[non_exhaustive]
pub enum Error {
    /// The request could not be sent, or the response could not be read
    /// (DNS failure, connection reset, TLS error, ...).
    #[error("transport error")]
    Transport(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// The request timed out waiting for a response.
    #[error("request timed out")]
    Timeout,

    /// The provider rejected the request because of rate limiting.
    ///
    /// `#[non_exhaustive]`: construct with [`Error::rate_limited`], not a
    /// struct literal, so a future field can be added without a breaking
    /// release.
    #[error("rate limited")]
    #[non_exhaustive]
    RateLimited {
        /// How long the provider asked the caller to wait before retrying,
        /// if it said so (e.g. via a `Retry-After` header).
        retry_after: Option<Duration>,
    },

    /// The provider returned an error response for an otherwise
    /// well-formed request.
    ///
    /// `#[non_exhaustive]`: construct with [`Error::api`] plus the
    /// `with_*` setters below, not a struct literal, so a future field can
    /// be added without a breaking release.
    #[error("provider error {status}")]
    #[non_exhaustive]
    Api {
        /// HTTP status code returned by the provider.
        status: u16,
        /// The name of the request field the provider blamed for this
        /// error, if it identified one. This is *not* a stable,
        /// machine-readable error code: Mollie, for example, populates it
        /// from its response's `field` property, which is a field name
        /// like `"amount"`, not an error code from a fixed enumeration.
        code: Option<String>,
        /// Human-readable summary of the error. Free-form provider text —
        /// like `detail` and `raw_body`, not included in `Display` or
        /// `Debug` output, since a provider echoing request content back
        /// into it is a realistic leak path. See the module-level
        /// "Security" section. Access it via [`Error::title`] when you
        /// know it is safe to log.
        title: String,
        /// Additional structured detail, if the provider supplied any.
        /// Free-form provider text — like `title` and `raw_body`, not
        /// included in `Display` or `Debug` output. See the module-level
        /// "Security" section. Access it via [`Error::detail`] when you
        /// know it is safe to log.
        detail: Option<String>,
        /// The raw response body, if it was captured. Not included in
        /// `Display` or `Debug` output — see [`Error::raw_body`].
        raw_body: Option<String>,
    },

    /// The requested resource does not exist at the provider.
    ///
    /// A misconfigured base URL also surfaces here, so the provider's own
    /// response body is worth capturing: "payment not found" alone is a
    /// misleading message for what is actually a configuration bug.
    ///
    /// `#[non_exhaustive]`: construct with [`Error::not_found`].
    #[error("payment not found")]
    #[non_exhaustive]
    NotFound {
        /// The raw response body, if it was captured. Not included in
        /// `Display` or `Debug` output — see [`Error::raw_body`].
        raw_body: Option<String>,
    },

    /// The provider rejected the request's credentials.
    ///
    /// Covers both 401 and 403. The distinction usually lives only in the
    /// response body — a 403 from Mollie is typically a test key used
    /// against a live payment, or an inactive profile, neither of which is
    /// diagnosable from the status code alone.
    ///
    /// `#[non_exhaustive]`: construct with [`Error::unauthorized`].
    #[error("unauthorized: invalid or missing API credentials")]
    #[non_exhaustive]
    Unauthorized {
        /// The raw response body, if it was captured. Not included in
        /// `Display` or `Debug` output — see [`Error::raw_body`].
        raw_body: Option<String>,
    },

    /// The request was rejected before it reached the provider, or by the
    /// provider, because it was malformed.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// The amount reported by the provider does not match the amount
    /// expected by the caller.
    ///
    /// Providers should compare this against their own stored order total
    /// before treating a payment as settled — see the crate-level
    /// documentation.
    #[error("amount mismatch: expected {expected}, got {actual}")]
    AmountMismatch {
        /// The amount the caller expected.
        expected: Money,
        /// The amount the provider actually reported.
        actual: Money,
    },

    /// The provider's response could not be decoded into the expected
    /// shape.
    ///
    /// `#[non_exhaustive]`: construct with [`Error::decode`], not a struct
    /// literal, so a future field can be added without a breaking release.
    #[error("failed to decode provider response: {message}")]
    #[non_exhaustive]
    Decode {
        /// Description of what failed to decode.
        message: String,
        /// The raw response body that failed to decode, if it was
        /// captured. Not included in `Display` or `Debug` output — see
        /// [`Error::raw_body`].
        raw_body: Option<String>,
    },

    /// The operation is not supported by this provider implementation.
    #[error("operation not supported by this provider")]
    Unsupported,

    /// The provider reports the payment as not (yet) paid.
    ///
    /// Returned by
    /// [`PaymentProvider::fetch_verified`](crate::provider::PaymentProvider::fetch_verified)'s
    /// default implementation when the fetched payment's amount matches
    /// the expected value but its status is not [`PaymentStatus::Paid`].
    /// Not retriable in the sense of "safe to immediately resend the same
    /// call" — an unpaid status rarely changes within milliseconds, so
    /// callers should defer to their own polling or webhook cadence
    /// instead of looping on this call.
    ///
    /// `#[non_exhaustive]`: construct with [`Error::not_paid`], not a
    /// struct literal, so a future field can be added without a breaking
    /// release.
    #[error("payment not paid: current status is {status}")]
    #[non_exhaustive]
    NotPaid {
        /// The payment's actual status at the provider.
        status: PaymentStatus,
    },
}

impl Error {
    /// Returns `true` when retrying the same call could plausibly succeed.
    ///
    /// `true` for [`Error::Transport`], [`Error::Timeout`],
    /// [`Error::RateLimited`], and [`Error::Api`] with a `5xx` status.
    ///
    /// `false` for everything else, including [`Error::Api`] with a `4xx`
    /// status: the request itself was rejected and resending it unchanged
    /// will not help.
    #[must_use]
    pub fn is_retriable(&self) -> bool {
        match self {
            Self::Transport(_) | Self::Timeout | Self::RateLimited { .. } => true,
            Self::Api { status, .. } => (500..600).contains(status),
            Self::NotFound { .. }
            | Self::Unauthorized { .. }
            | Self::InvalidRequest(_)
            | Self::AmountMismatch { .. }
            | Self::Decode { .. }
            | Self::Unsupported
            | Self::NotPaid { .. } => false,
        }
    }

    /// Returns the raw provider response body, when one was captured.
    ///
    /// Only [`Error::Api`], [`Error::Decode`], [`Error::NotFound`] and
    /// [`Error::Unauthorized`] can carry a body; all other variants return
    /// `None`.
    ///
    /// The body is provider-controlled and may contain sensitive data. It
    /// is intentionally not part of the `Display` or `Debug` output —
    /// callers must opt in by calling this method, and must not log or
    /// expose the result without knowing it is safe to do so in their
    /// context.
    #[must_use]
    pub fn raw_body(&self) -> Option<&str> {
        match self {
            Self::Api { raw_body, .. }
            | Self::Decode { raw_body, .. }
            | Self::NotFound { raw_body }
            | Self::Unauthorized { raw_body } => raw_body.as_deref(),
            Self::Transport(_)
            | Self::Timeout
            | Self::RateLimited { .. }
            | Self::InvalidRequest(_)
            | Self::AmountMismatch { .. }
            | Self::Unsupported
            | Self::NotPaid { .. } => None,
        }
    }

    /// Returns the [`Error::Api`] `title` field, when this is an
    /// [`Error::Api`].
    ///
    /// `title` is provider-controlled, free-form text and may contain
    /// sensitive data (see the module-level "Security" section). It is
    /// intentionally not part of the `Display` or `Debug` output — callers
    /// must opt in by calling this method, and must not log or expose the
    /// result without knowing it is safe to do so in their context.
    #[must_use]
    pub fn title(&self) -> Option<&str> {
        match self {
            Self::Api { title, .. } => Some(title),
            Self::Transport(_)
            | Self::Timeout
            | Self::RateLimited { .. }
            | Self::NotFound { .. }
            | Self::Unauthorized { .. }
            | Self::InvalidRequest(_)
            | Self::AmountMismatch { .. }
            | Self::Decode { .. }
            | Self::Unsupported
            | Self::NotPaid { .. } => None,
        }
    }

    /// Returns the [`Error::Api`] `detail` field, when this is an
    /// [`Error::Api`] and the provider supplied one.
    ///
    /// `detail` is provider-controlled, free-form text and may contain
    /// sensitive data (see the module-level "Security" section). It is
    /// intentionally not part of the `Display` or `Debug` output — callers
    /// must opt in by calling this method, and must not log or expose the
    /// result without knowing it is safe to do so in their context.
    #[must_use]
    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::Api { detail, .. } => detail.as_deref(),
            Self::Transport(_)
            | Self::Timeout
            | Self::RateLimited { .. }
            | Self::NotFound { .. }
            | Self::Unauthorized { .. }
            | Self::InvalidRequest(_)
            | Self::AmountMismatch { .. }
            | Self::Decode { .. }
            | Self::Unsupported
            | Self::NotPaid { .. } => None,
        }
    }

    /// Creates an [`Error::NotFound`] with no body captured. Chain
    /// [`Error::with_raw_body`] to attach one.
    ///
    /// The only public way to construct this variant now that it is
    /// `#[non_exhaustive]`.
    #[must_use]
    pub fn not_found() -> Self {
        Self::NotFound { raw_body: None }
    }

    /// Creates an [`Error::Unauthorized`] with no body captured. Chain
    /// [`Error::with_raw_body`] to attach one.
    ///
    /// The only public way to construct this variant now that it is
    /// `#[non_exhaustive]`.
    #[must_use]
    pub fn unauthorized() -> Self {
        Self::Unauthorized { raw_body: None }
    }

    /// Creates an [`Error::RateLimited`].
    ///
    /// The only public way to construct this variant now that it is
    /// `#[non_exhaustive]` — required so third-party
    /// [`PaymentProvider`](crate::provider::PaymentProvider)
    /// implementations can still report rate limiting.
    #[must_use]
    pub fn rate_limited(retry_after: Option<Duration>) -> Self {
        Self::RateLimited { retry_after }
    }

    /// Creates an [`Error::Api`] with no `code`, `detail`, or `raw_body`
    /// set. Chain [`Error::with_code`], [`Error::with_detail`], and/or
    /// [`Error::with_raw_body`] to fill those in.
    ///
    /// The only public way to construct this variant now that it is
    /// `#[non_exhaustive]` — required so third-party
    /// [`PaymentProvider`](crate::provider::PaymentProvider)
    /// implementations can still report a provider error response.
    #[must_use]
    pub fn api(status: u16, title: impl Into<String>) -> Self {
        Self::Api {
            status,
            code: None,
            title: title.into(),
            detail: None,
            raw_body: None,
        }
    }

    /// Sets the `code` field on an [`Error::Api`]. A no-op on every other
    /// variant.
    #[must_use]
    pub fn with_code(mut self, code: impl Into<String>) -> Self {
        if let Self::Api { code: c, .. } = &mut self {
            *c = Some(code.into());
        }
        self
    }

    /// Sets the `detail` field on an [`Error::Api`]. A no-op on every
    /// other variant.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        if let Self::Api { detail: d, .. } = &mut self {
            *d = Some(detail.into());
        }
        self
    }

    /// Sets the `raw_body` field on an [`Error::Api`], [`Error::Decode`],
    /// [`Error::NotFound`], or [`Error::Unauthorized`]. A no-op on every
    /// other variant.
    #[must_use]
    pub fn with_raw_body(mut self, raw_body: impl Into<String>) -> Self {
        match &mut self {
            Self::Api { raw_body: b, .. }
            | Self::Decode { raw_body: b, .. }
            | Self::NotFound { raw_body: b }
            | Self::Unauthorized { raw_body: b } => {
                *b = Some(raw_body.into());
            }
            Self::Transport(_)
            | Self::Timeout
            | Self::RateLimited { .. }
            | Self::InvalidRequest(_)
            | Self::AmountMismatch { .. }
            | Self::Unsupported
            | Self::NotPaid { .. } => {}
        }
        self
    }

    /// Creates an [`Error::Decode`] with no `raw_body` set. Chain
    /// [`Error::with_raw_body`] to attach one.
    ///
    /// The only public way to construct this variant now that it is
    /// `#[non_exhaustive]` — required so third-party
    /// [`PaymentProvider`](crate::provider::PaymentProvider)
    /// implementations can still report a decode failure.
    #[must_use]
    pub fn decode(message: impl Into<String>) -> Self {
        Self::Decode {
            message: message.into(),
            raw_body: None,
        }
    }

    /// Creates an [`Error::NotPaid`].
    ///
    /// The only public way to construct this variant now that it is
    /// `#[non_exhaustive]` — required so a
    /// [`PaymentProvider`](crate::provider::PaymentProvider) implementation
    /// that overrides
    /// [`fetch_verified`](crate::provider::PaymentProvider::fetch_verified)
    /// can still report an unpaid payment.
    #[must_use]
    pub fn not_paid(status: PaymentStatus) -> Self {
        Self::NotPaid { status }
    }
}

// Implemented by hand (rather than `#[derive(Debug)]`) so that fields which
// may hold a raw provider response body are never printed, and so that the
// `Transport` variant never formats its inner source (which could itself
// embed sensitive data, e.g. a URL with credentials).
impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(_) => f
                .debug_tuple("Transport")
                .field(&"<source elided>")
                .finish(),
            Self::Timeout => write!(f, "Timeout"),
            Self::RateLimited { retry_after } => f
                .debug_struct("RateLimited")
                .field("retry_after", retry_after)
                .finish(),
            Self::Api { status, code, .. } => f
                .debug_struct("Api")
                .field("status", status)
                .field("code", code)
                .field("title", &"<redacted>")
                .field("detail", &"<redacted>")
                .field("raw_body", &"<redacted>")
                .finish(),
            Self::NotFound { .. } => f
                .debug_struct("NotFound")
                .field("raw_body", &"<redacted>")
                .finish(),
            Self::Unauthorized { .. } => f
                .debug_struct("Unauthorized")
                .field("raw_body", &"<redacted>")
                .finish(),
            Self::InvalidRequest(message) => {
                f.debug_tuple("InvalidRequest").field(message).finish()
            }
            Self::AmountMismatch { expected, actual } => f
                .debug_struct("AmountMismatch")
                .field("expected", expected)
                .field("actual", actual)
                .finish(),
            Self::Decode { message, .. } => f
                .debug_struct("Decode")
                .field("message", message)
                .field("raw_body", &"<redacted>")
                .finish(),
            Self::Unsupported => write!(f, "Unsupported"),
            Self::NotPaid { status } => f.debug_struct("NotPaid").field("status", status).finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::money::Currency;

    fn amount() -> Money {
        Money::from_minor(1000, Currency::EUR)
    }

    // --- is_retriable ---

    #[test]
    fn transport_is_retriable() {
        let err = Error::Transport(Box::new(std::io::Error::other("boom")));
        assert!(err.is_retriable());
    }

    #[test]
    fn timeout_is_retriable() {
        assert!(Error::Timeout.is_retriable());
    }

    #[test]
    fn rate_limited_is_retriable() {
        let err = Error::RateLimited {
            retry_after: Some(Duration::from_secs(1)),
        };
        assert!(err.is_retriable());
        assert!(Error::RateLimited { retry_after: None }.is_retriable());
    }

    #[test]
    fn api_5xx_is_retriable() {
        let err = Error::Api {
            status: 503,
            code: None,
            title: "Service Unavailable".into(),
            detail: None,
            raw_body: None,
        };
        assert!(err.is_retriable());
    }

    #[test]
    fn api_4xx_is_not_retriable() {
        let err = Error::Api {
            status: 401,
            code: None,
            title: "Unauthorized".into(),
            detail: None,
            raw_body: None,
        };
        assert!(!err.is_retriable());
    }

    #[test]
    fn not_found_is_not_retriable() {
        assert!(!Error::not_found().is_retriable());
    }

    #[test]
    fn unauthorized_is_not_retriable() {
        assert!(!Error::unauthorized().is_retriable());
    }

    #[test]
    fn invalid_request_is_not_retriable() {
        assert!(!Error::InvalidRequest("bad field".into()).is_retriable());
    }

    #[test]
    fn amount_mismatch_is_not_retriable() {
        let err = Error::AmountMismatch {
            expected: amount(),
            actual: Money::from_minor(500, Currency::EUR),
        };
        assert!(!err.is_retriable());
    }

    #[test]
    fn decode_is_not_retriable() {
        let err = Error::Decode {
            message: "unexpected shape".into(),
            raw_body: None,
        };
        assert!(!err.is_retriable());
    }

    #[test]
    fn unsupported_is_not_retriable() {
        assert!(!Error::Unsupported.is_retriable());
    }

    #[test]
    fn not_paid_is_not_retriable() {
        assert!(!Error::not_paid(crate::payment::PaymentStatus::Open).is_retriable());
    }

    // --- raw_body ---

    #[test]
    fn api_raw_body_is_reachable() {
        let err = Error::Api {
            status: 422,
            code: None,
            title: "Invalid".into(),
            detail: None,
            raw_body: Some("{\"raw\":true}".into()),
        };
        assert_eq!(err.raw_body(), Some("{\"raw\":true}"));
    }

    #[test]
    fn decode_raw_body_is_reachable() {
        let err = Error::Decode {
            message: "bad json".into(),
            raw_body: Some("not json".into()),
        };
        assert_eq!(err.raw_body(), Some("not json"));
    }

    // --- title / detail accessors ---

    #[test]
    fn api_title_is_reachable() {
        let err = Error::api(422, "Invalid request");
        assert_eq!(err.title(), Some("Invalid request"));
    }

    #[test]
    fn api_detail_is_reachable() {
        let err = Error::api(422, "Invalid request").with_detail("amount is required");
        assert_eq!(err.detail(), Some("amount is required"));
    }

    #[test]
    fn api_detail_is_none_when_unset() {
        let err = Error::api(422, "Invalid request");
        assert_eq!(err.detail(), None);
    }

    #[test]
    fn variants_without_a_title_or_detail_return_none() {
        assert_eq!(Error::Timeout.title(), None);
        assert_eq!(Error::Timeout.detail(), None);
        assert_eq!(Error::not_found().title(), None);
        assert_eq!(Error::not_found().detail(), None);
    }

    #[test]
    fn not_found_and_unauthorized_carry_a_body_without_leaking_it() {
        // A 403 body is often the only thing distinguishing "test key against a
        // live payment" from an inactive profile, so it must be retrievable —
        // but never through Display or Debug.
        for err in [
            Error::not_found().with_raw_body(FAKE_API_KEY),
            Error::unauthorized().with_raw_body(FAKE_API_KEY),
        ] {
            assert_eq!(err.raw_body(), Some(FAKE_API_KEY));
            assert!(!format!("{err}").contains(FAKE_API_KEY));
            assert!(!format!("{err:?}").contains(FAKE_API_KEY));
        }
    }

    #[test]
    fn variants_without_a_body_return_none() {
        assert_eq!(Error::Timeout.raw_body(), None);
        assert_eq!(Error::Unsupported.raw_body(), None);
        // These two *can* carry a body, but do not until one is attached.
        assert_eq!(Error::not_found().raw_body(), None);
        assert_eq!(Error::unauthorized().raw_body(), None);
        assert_eq!(Error::InvalidRequest("x".into()).raw_body(), None);
        assert_eq!(Error::RateLimited { retry_after: None }.raw_body(), None);
        assert_eq!(
            Error::Transport(Box::new(std::io::Error::other("boom"))).raw_body(),
            None
        );
        assert_eq!(
            Error::AmountMismatch {
                expected: amount(),
                actual: amount(),
            }
            .raw_body(),
            None
        );
    }

    // --- source() ---

    #[test]
    fn transport_exposes_a_source() {
        let err = Error::Transport(Box::new(std::io::Error::other("boom")));
        assert!(std::error::Error::source(&err).is_some());
    }

    #[test]
    fn variants_without_an_inner_error_have_no_source() {
        assert!(std::error::Error::source(&Error::Timeout).is_none());
        assert!(std::error::Error::source(&Error::not_found()).is_none());
        assert!(std::error::Error::source(&Error::unauthorized()).is_none());
    }

    // --- security: raw body never appears in Display ---

    const SENSITIVE_BODY: &str = "{\"card_number\":\"4111111111111111\"}";

    #[test]
    fn api_display_never_contains_raw_body() {
        let err = Error::Api {
            status: 422,
            code: Some("invalid".into()),
            title: "Invalid request".into(),
            detail: Some("safe summary".into()),
            raw_body: Some(SENSITIVE_BODY.into()),
        };
        assert!(!format!("{err}").contains(SENSITIVE_BODY));
    }

    #[test]
    fn api_display_contains_neither_title_nor_detail() {
        // `title` and `detail` are both free-form provider text — neither
        // belongs in `Display`, only the status code does.
        let err = Error::api(422, "Invalid request").with_detail("safe-looking summary");
        let display = format!("{err}");
        assert!(!display.contains("Invalid request"));
        assert!(!display.contains("safe-looking summary"));
        assert_eq!(display, "provider error 422");
    }

    #[test]
    fn api_debug_contains_neither_title_nor_detail() {
        let err = Error::api(422, "Invalid request").with_detail("safe-looking summary");
        let debug = format!("{err:?}");
        assert!(!debug.contains("Invalid request"));
        assert!(!debug.contains("safe-looking summary"));
    }

    #[test]
    fn decode_display_never_contains_raw_body() {
        let err = Error::Decode {
            message: "unexpected shape".into(),
            raw_body: Some(SENSITIVE_BODY.into()),
        };
        assert!(!format!("{err}").contains(SENSITIVE_BODY));
    }

    // --- security: an API key never appears in Display or Debug, for any variant ---

    const FAKE_API_KEY: &str = "sk_live_FAKETESTKEY1234567890";

    #[test]
    fn api_key_in_raw_body_never_leaks() {
        let err = Error::Api {
            status: 400,
            code: None,
            title: "Bad request".into(),
            detail: None,
            raw_body: Some(format!("Authorization: Bearer {FAKE_API_KEY}")),
        };
        assert!(!format!("{err}").contains(FAKE_API_KEY));
        assert!(!format!("{err:?}").contains(FAKE_API_KEY));
    }

    // `title` and `detail` are the same class of data: both are free-form
    // text a provider (or a proxy in front of one) supplied. A credential
    // planted in `title` must be just as redacted as one in `detail` or
    // `raw_body` — this is the bug this round of tests demonstrates:
    // previously only `detail` was covered, and `title` leaked through both
    // `Display` and `Debug`.
    #[test]
    fn api_key_in_title_never_leaks() {
        let err = Error::api(422, format!("Bearer {FAKE_API_KEY}"));
        assert!(!format!("{err}").contains(FAKE_API_KEY));
        assert!(!format!("{err:?}").contains(FAKE_API_KEY));
    }

    #[test]
    fn api_key_in_detail_never_leaks() {
        let err = Error::api(422, "Invalid request").with_detail(format!("Bearer {FAKE_API_KEY}"));
        assert!(!format!("{err}").contains(FAKE_API_KEY));
        assert!(!format!("{err:?}").contains(FAKE_API_KEY));
    }

    #[test]
    fn api_key_in_decode_raw_body_never_leaks() {
        let err = Error::Decode {
            message: "unexpected shape".into(),
            raw_body: Some(format!("Authorization: Bearer {FAKE_API_KEY}")),
        };
        assert!(!format!("{err}").contains(FAKE_API_KEY));
        assert!(!format!("{err:?}").contains(FAKE_API_KEY));
    }

    #[test]
    fn api_key_in_transport_source_never_leaks() {
        // Simulates a low-level transport error whose own Display/Debug
        // happens to embed a credential (e.g. a URL with an embedded key).
        #[derive(Debug)]
        struct LeakySource;
        impl std::fmt::Display for LeakySource {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(
                    f,
                    "connect to https://user:{FAKE_API_KEY}@example.com failed"
                )
            }
        }
        impl std::error::Error for LeakySource {}

        let err = Error::Transport(Box::new(LeakySource));
        assert!(!format!("{err}").contains(FAKE_API_KEY));
        assert!(!format!("{err:?}").contains(FAKE_API_KEY));
    }

    #[test]
    fn variants_without_any_sensitive_field_cannot_leak_a_key() {
        for err in [
            Error::Timeout,
            Error::not_found(),
            Error::unauthorized(),
            Error::Unsupported,
            Error::RateLimited { retry_after: None },
        ] {
            assert!(!format!("{err}").contains(FAKE_API_KEY));
            assert!(!format!("{err:?}").contains(FAKE_API_KEY));
        }
    }

    // --- constructors: every #[non_exhaustive] variant must remain
    // constructible from outside this crate without a struct literal. ---
    //
    // These calls deliberately use only the public constructors/setters —
    // never a struct literal — to demonstrate what a third-party
    // `PaymentProvider` implementation (which cannot use struct-literal
    // syntax on a `#[non_exhaustive]` variant) is able to produce.

    #[test]
    fn rate_limited_constructor_round_trips_the_field() {
        let err = Error::rate_limited(Some(Duration::from_secs(5)));
        match err {
            Error::RateLimited { retry_after } => {
                assert_eq!(retry_after, Some(Duration::from_secs(5)));
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[test]
    fn api_constructor_and_setters_populate_every_field() {
        let err = Error::api(422, "Unprocessable Entity")
            .with_code("amount")
            .with_detail("amount is required")
            .with_raw_body("{\"field\":\"amount\"}");
        match err {
            Error::Api {
                status,
                code,
                title,
                detail,
                raw_body,
            } => {
                assert_eq!(status, 422);
                assert_eq!(code.as_deref(), Some("amount"));
                assert_eq!(title, "Unprocessable Entity");
                assert_eq!(detail.as_deref(), Some("amount is required"));
                assert_eq!(raw_body.as_deref(), Some("{\"field\":\"amount\"}"));
            }
            other => panic!("expected Api, got {other:?}"),
        }
    }

    #[test]
    fn api_constructor_alone_leaves_optional_fields_unset() {
        let err = Error::api(500, "Internal Server Error");
        match err {
            Error::Api {
                status,
                code,
                title,
                detail,
                raw_body,
            } => {
                assert_eq!(status, 500);
                assert_eq!(code, None);
                assert_eq!(title, "Internal Server Error");
                assert_eq!(detail, None);
                assert_eq!(raw_body, None);
            }
            other => panic!("expected Api, got {other:?}"),
        }
    }

    #[test]
    fn with_code_with_detail_and_with_raw_body_are_no_ops_on_variants_that_do_not_carry_them() {
        // These setters only make sense on `Error::Api` (`with_code`,
        // `with_detail`) or `Api`/`Decode`/`NotFound`/`Unauthorized`
        // (`with_raw_body`); applying them to an unrelated variant must not
        // panic or otherwise corrupt it.
        let err = Error::Timeout
            .with_code("x")
            .with_detail("y")
            .with_raw_body("z");
        assert!(matches!(err, Error::Timeout));
    }

    #[test]
    fn decode_constructor_and_setter_populate_every_field() {
        let err = Error::decode("unexpected shape").with_raw_body("not json");
        match err {
            Error::Decode { message, raw_body } => {
                assert_eq!(message, "unexpected shape");
                assert_eq!(raw_body.as_deref(), Some("not json"));
            }
            other => panic!("expected Decode, got {other:?}"),
        }
    }

    #[test]
    fn not_paid_constructor_round_trips_the_status() {
        let err = Error::not_paid(crate::payment::PaymentStatus::Pending);
        match err {
            Error::NotPaid { status } => {
                assert_eq!(status, crate::payment::PaymentStatus::Pending);
            }
            other => panic!("expected NotPaid, got {other:?}"),
        }
    }

    #[test]
    fn not_paid_display_includes_the_actual_status() {
        let err = Error::not_paid(crate::payment::PaymentStatus::Open);
        assert!(format!("{err}").contains("open"));
    }
}
