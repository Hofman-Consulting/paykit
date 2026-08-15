//! Mollie payment provider.
//!
//! [`MollieProvider`] implements [`PaymentProvider`] against Mollie's
//! [Payments API](https://docs.mollie.com/reference/v2/payments-api/overview).
//!
//! # Security
//!
//! Mollie does not sign webhook notifications: the only trustworthy content
//! in one is the payment id. Everything else — including the amount — must
//! be re-fetched from the API and checked against a value you already know.
//! [`PaymentProvider::fetch_verified`] does exactly that and is the
//! recommended way to handle a webhook. See its documentation for what it
//! does and does not prove.
//!
//! The API key given to [`MollieProvider::new`] / [`MollieProvider::builder`]
//! is attached as a bearer token to every request this provider sends. To
//! keep that from leaking:
//!
//! - [`MollieProvider`] and [`MollieProviderBuilder`] do not derive `Debug`,
//!   `Display`, or `Serialize`. [`MollieProvider`]'s hand-written `Debug`
//!   redacts the key.
//! - The key is stored as a [`reqwest::header::HeaderValue`] marked
//!   [`set_sensitive`](reqwest::header::HeaderValue::set_sensitive), which
//!   keeps it out of HPACK's dynamic table on the wire and out of `http`'s
//!   own `Debug` output.
//! - [`MollieProviderBuilder::base_url`] only accepts `https://` origins
//!   with no userinfo, query string, or fragment, since the key is attached
//!   unconditionally to whatever origin the provider is pointed at. Tests
//!   that need a plain-`http` mock server use
//!   [`MollieProviderBuilder::insecure_base_url_for_testing`] instead.
//! - An internally-built client never follows redirects, so a redirect
//!   response can't be used to forward the `Authorization` header to a
//!   different host. A client supplied via
//!   [`MollieProviderBuilder::client`] / [`MollieProvider::with_client`]
//!   keeps whatever redirect policy the caller configured — that's the
//!   caller's responsibility.

mod types;

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{HeaderValue, AUTHORIZATION, RETRY_AFTER};
use reqwest::Method;
use serde::de::DeserializeOwned;

use crate::error::Error;
use crate::money::{Currency, Money};
use crate::payment::{CreatePayment, Payment, PaymentStatus, Refund, RefundRequest, RefundStatus};
use crate::provider::PaymentProvider;
use types::{
    CreatePaymentBody, CreateRefundBody, MollieAmount, MollieErrorBody, MolliePayment, MollieRefund,
};

pub mod webhook;

/// Mollie's production API base URL.
const DEFAULT_BASE_URL: &str = "https://api.mollie.com/v2";

/// Cap on how many bytes of a single provider response this client will
/// buffer in memory, for both success and error responses. An unbounded
/// read from a wedged or hostile endpoint could otherwise OOM the process;
/// no legitimate Mollie response comes close to this size.
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

/// Default total-request timeout for an internally-built client.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default connect timeout for an internally-built client.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Default idle-connection pool size per host for an internally-built
/// client.
const DEFAULT_POOL_MAX_IDLE_PER_HOST: usize = 4;

/// Metadata key paykit uses to round-trip [`CreatePayment`]'s reference
/// through Mollie's free-form `metadata` object (Mollie has no first-class
/// reference field). [`build_metadata`] rejects a caller-supplied metadata
/// entry under this key outright, rather than silently merging over — or
/// being overwritten by — it.
const REFERENCE_METADATA_KEY: &str = "paykit_reference";

/// Mollie payment provider.
///
/// Construct with [`MollieProvider::new`] (internally-built HTTP client),
/// [`MollieProvider::with_client`] (caller-supplied, preferred when the
/// application already owns a [`reqwest::Client`]), or
/// [`MollieProvider::builder`] for finer control.
///
/// Cheap to clone: every field is either a plain `String` or, like
/// [`reqwest::Client`], internally reference-counted.
///
/// Implements [`PaymentProvider`]. See the [module docs](self) for the
/// security properties this type upholds around its API key.
#[derive(Clone)]
pub struct MollieProvider {
    base_url: String,
    client: reqwest::Client,
    auth_header: HeaderValue,
}

// Hand-written rather than derived so the API key is redacted rather than
// printed. `auth_header` itself would already redact via `http`'s own
// `Debug` (it is marked sensitive), but it is left out entirely here rather
// than relying on that as the only line of defense.
impl fmt::Debug for MollieProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MollieProvider")
            .field("base_url", &self.base_url)
            .field("api_key", &"***")
            .finish_non_exhaustive()
    }
}

impl MollieProvider {
    /// Starts building a provider with non-default configuration. See
    /// [`MollieProviderBuilder`].
    #[must_use]
    pub fn builder(api_key: impl Into<String>) -> MollieProviderBuilder {
        MollieProviderBuilder::new(api_key.into())
    }

    /// Creates a provider with an internally-built HTTP client, using this
    /// crate's opinionated defaults: a 5 second connect timeout, a 10 second
    /// total request timeout, 4 idle connections pooled per host, and no
    /// redirect following. Use [`MollieProvider::builder`] to override any
    /// of these, or [`MollieProvider::with_client`] to supply your own
    /// client outright.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidRequest`] if `api_key` contains bytes that
    /// are not valid in an HTTP header value, or if the internal HTTP client
    /// could not be built. Never panics.
    pub fn new(api_key: impl Into<String>) -> Result<Self, Error> {
        Self::builder(api_key).build()
    }

    /// Creates a provider that sends requests through a caller-supplied
    /// [`reqwest::Client`].
    ///
    /// **Preferred** over [`MollieProvider::new`] in an application that
    /// already owns a `Client`: sharing one keeps connection pooling and TLS
    /// session resumption working across payment creation, webhook
    /// verification, and any reconciliation sweep, instead of each paying
    /// for its own connection setup. The supplied client's redirect policy
    /// is the caller's responsibility — see the [module docs](self).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidRequest`] if `api_key` contains bytes that
    /// are not valid in an HTTP header value. Never panics.
    pub fn with_client(api_key: impl Into<String>, client: reqwest::Client) -> Result<Self, Error> {
        Self::builder(api_key).client(client).build()
    }

    fn request(&self, method: Method, path: &str) -> reqwest::RequestBuilder {
        let url = format!("{}{path}", self.base_url);
        self.client
            .request(method, url)
            .header(AUTHORIZATION, self.auth_header.clone())
    }

    async fn send(&self, builder: reqwest::RequestBuilder) -> Result<reqwest::Response, Error> {
        builder.send().await.map_err(map_transport_error)
    }

    /// Sends `builder` and decodes a successful (2xx) JSON response into
    /// `T`, or maps a non-2xx response into the appropriate [`Error`]
    /// variant.
    async fn send_json<T: DeserializeOwned>(
        &self,
        builder: reqwest::RequestBuilder,
    ) -> Result<T, Error> {
        let response = self.send(builder).await?;
        if response.status().is_success() {
            decode_json(response).await
        } else {
            Err(build_error_response(response).await)
        }
    }
}

#[async_trait]
impl PaymentProvider for MollieProvider {
    async fn create_payment(&self, req: CreatePayment) -> Result<Payment, Error> {
        req.validate()?;

        let amount = req.amount();
        let body = CreatePaymentBody {
            amount: MollieAmount::from(amount),
            description: req.description().to_string(),
            redirect_url: req.redirect_url().to_string(),
            webhook_url: req.webhook_url().map(str::to_string),
            metadata: build_metadata(req.reference(), req.metadata())?,
        };

        // `req.idempotency_key()` is always populated (materialized by
        // `CreatePayment::new`), and — critically — the *same* value on
        // every call for a given `req`. Generating a fresh key here on
        // every call would defeat the point of an idempotency key: a caller
        // retrying after a timeout (which `Error::is_retriable` invites)
        // would create a second, live payment instead of Mollie recognizing
        // the retry and returning the first one.
        let builder = self
            .request(Method::POST, "/payments")
            .header("Idempotency-Key", req.idempotency_key())
            .json(&body);

        let wire: MolliePayment = self.send_json(builder).await?;
        let payment = payment_from_wire(wire)?;
        // Mirrors the id check in `get_payment`/`cancel_payment`: never
        // trust an echoed value without checking it against what was asked
        // for. A caller that persists this returned amount and later feeds
        // it to `fetch_verified` would otherwise be comparing provider data
        // against provider data.
        if payment.amount != amount {
            return Err(Error::decode(format!(
                "created a payment for {amount} but the provider echoed back {}",
                payment.amount
            )));
        }
        Ok(payment)
    }

    async fn get_payment(&self, id: &str) -> Result<Payment, Error> {
        let id = validate_payment_id(id)?;
        let path = format!("/payments/{}", encode_path_segment(id));
        let wire: MolliePayment = self.send_json(self.request(Method::GET, &path)).await?;
        let payment = payment_from_wire(wire)?;
        if payment.id != id {
            return Err(Error::decode(format!(
                "requested payment {id:?} but the provider returned payment {:?}",
                payment.id
            )));
        }
        Ok(payment)
    }

    async fn cancel_payment(&self, id: &str) -> Result<Payment, Error> {
        let id = validate_payment_id(id)?;
        let path = format!("/payments/{}", encode_path_segment(id));
        // Mollie returns the updated payment resource on a successful
        // DELETE, not a bare 204 — decode and hand it back rather than
        // discarding it.
        let wire: MolliePayment = self.send_json(self.request(Method::DELETE, &path)).await?;
        let payment = payment_from_wire(wire)?;
        if payment.id != id {
            return Err(Error::decode(format!(
                "requested to cancel payment {id:?} but the provider returned payment {:?}",
                payment.id
            )));
        }
        Ok(payment)
    }

    async fn refund(&self, id: &str, req: RefundRequest) -> Result<Refund, Error> {
        let id = validate_payment_id(id)?;
        let path = format!("/payments/{}/refunds", encode_path_segment(id));
        // `amount` is always sent: Mollie's refund endpoint documents it as
        // required and returns a 422 without it, so the previous
        // "omit for a full refund" behavior always failed in production.
        // `RefundRequest::amount` is required at construction time, so
        // there is no `Option` to omit here in the first place.
        let body = CreateRefundBody {
            amount: MollieAmount::from(req.amount()),
            description: req.description().map(str::to_string),
        };

        // `RefundRequest::new` generates an idempotency key eagerly, exactly
        // like `CreatePayment::new` (see its doc comment for why), so it is
        // always present here and attached unconditionally — mirroring
        // `create_payment` above. Omitting the header on a retry, as this
        // used to do whenever the caller had not called
        // `with_idempotency_key` themselves, would make Mollie treat the
        // retry as a brand new refund: following this crate's own
        // `Error::is_retriable` protocol (retry on timeout/5xx) would then
        // issue a second, duplicate refund — a mistake that loses money just
        // as directly as a duplicate charge.
        let builder = self
            .request(Method::POST, &path)
            .header("Idempotency-Key", req.idempotency_key())
            .json(&body);

        let wire: MollieRefund = self.send_json(builder).await?;
        refund_from_wire(wire, id)
    }
}

/// Builder for [`MollieProvider`]. Construct via [`MollieProvider::builder`].
///
/// Does not implement `Debug`: it holds the same API key `MollieProvider`
/// does, before that key has been wrapped in a redacting `HeaderValue`.
pub struct MollieProviderBuilder {
    api_key: String,
    client: Option<reqwest::Client>,
    base_url: Result<String, Error>,
    timeout: Duration,
    connect_timeout: Duration,
}

impl MollieProviderBuilder {
    fn new(api_key: String) -> Self {
        Self {
            api_key,
            client: None,
            base_url: Ok(DEFAULT_BASE_URL.to_string()),
            timeout: DEFAULT_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
        }
    }

    /// Supplies a pre-built [`reqwest::Client`] instead of letting this
    /// builder construct one. See [`MollieProvider::with_client`] for why
    /// this is generally preferred.
    ///
    /// [`MollieProviderBuilder::timeout`], [`MollieProviderBuilder::connect_timeout`],
    /// and the internal no-redirect policy only apply to a client this
    /// builder constructs itself; once a client is supplied here, they have
    /// no effect and the supplied client's own configuration — including its
    /// redirect policy — is used as-is.
    #[must_use]
    pub fn client(mut self, client: reqwest::Client) -> Self {
        self.client = Some(client);
        self
    }

    /// Sets the API base URL. Must be an `https://` URL with no userinfo
    /// (`user:pass@host`), query string, or fragment — the API key this
    /// provider holds is attached to every request sent to it, so accepting
    /// an insecure or attacker-chosen origin here would hand that key over.
    /// A single trailing slash, if present, is stripped, so
    /// `https://api.mollie.com/v2` and `https://api.mollie.com/v2/` behave
    /// identically. Use
    /// [`MollieProviderBuilder::insecure_base_url_for_testing`] to point at
    /// a plain-`http` mock server in tests.
    ///
    /// Rejection is deferred to [`MollieProviderBuilder::build`], which
    /// returns [`Error::InvalidRequest`] if `url` was rejected here — this
    /// method's signature has no `Result` to return one from directly.
    #[must_use]
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        let url = url.into();
        self.base_url = if url.starts_with("https://") {
            normalize_base_url(url)
        } else {
            Err(Error::InvalidRequest(format!(
                "base_url must be an https:// URL, got {url:?}"
            )))
        };
        self
    }

    /// Sets the API base URL without requiring `https://`.
    ///
    /// **Never use this in production.** It exists only so tests can point
    /// the provider at a local plain-`http` mock server. This provider
    /// attaches its bearer token to every request unconditionally; using
    /// this for a real base URL hands that token to whatever is listening
    /// there in plaintext.
    ///
    /// Hidden from generated documentation, and **not covered by this
    /// crate's semver guarantees**: its signature or behavior may change in
    /// a patch release.
    #[doc(hidden)]
    #[must_use]
    pub fn insecure_base_url_for_testing(mut self, url: impl Into<String>) -> Self {
        self.base_url = normalize_base_url(url.into());
        self
    }

    /// Sets the total-request timeout for an internally-built client
    /// (default 10 seconds). No effect if [`MollieProviderBuilder::client`]
    /// was called.
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the connect timeout for an internally-built client (default 5
    /// seconds). No effect if [`MollieProviderBuilder::client`] was called.
    #[must_use]
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Builds the provider.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidRequest`] if `base_url` was rejected (see
    /// [`MollieProviderBuilder::base_url`]), if the API key contains bytes
    /// that are not valid in an HTTP header value, or if building an
    /// internal HTTP client failed. This never panics, unlike constructing a
    /// [`reqwest::Client`] with `.expect(..)`.
    pub fn build(self) -> Result<MollieProvider, Error> {
        let base_url = self.base_url?;
        let auth_header = build_auth_header(&self.api_key)?;
        let client = match self.client {
            Some(client) => client,
            None => reqwest::Client::builder()
                .connect_timeout(self.connect_timeout)
                .timeout(self.timeout)
                .pool_max_idle_per_host(DEFAULT_POOL_MAX_IDLE_PER_HOST)
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|err| {
                    Error::InvalidRequest(format!("failed to build internal HTTP client: {err}"))
                })?,
        };
        Ok(MollieProvider {
            base_url,
            client,
            auth_header,
        })
    }
}

/// Builds the `Authorization: Bearer <key>` header value, marked sensitive
/// so it is redacted from `http`'s own `Debug` output and excluded from
/// HPACK's dynamic table.
fn build_auth_header(api_key: &str) -> Result<HeaderValue, Error> {
    let mut value = HeaderValue::from_str(&format!("Bearer {api_key}")).map_err(|_| {
        Error::InvalidRequest(
            "api_key contains bytes that are not valid in an HTTP header value".to_string(),
        )
    })?;
    value.set_sensitive(true);
    Ok(value)
}

/// Rejects a `base_url` containing userinfo (`user:pass@host`), a query
/// string, or a fragment, and strips a single trailing slash so
/// `https://api.mollie.com/v2/` and `https://api.mollie.com/v2` produce
/// identical request paths instead of a double slash.
///
/// Userinfo is the sharpest edge this closes:
/// `https://api.mollie.com@evil.example/v2` has `api.mollie.com` as
/// *userinfo*, not the host — the request, and this provider's bearer
/// token, actually go to `evil.example`. A query string or fragment
/// appended here would land partway through every path this provider
/// builds (`{base_url}/payments/{id}`), corrupting it silently rather than
/// failing loudly.
///
/// This is a hand-rolled, minimal check rather than a dependency on the
/// `url` crate: `url` is only present transitively, via `reqwest`, not as a
/// direct dependency of this crate.
fn normalize_base_url(url: String) -> Result<String, Error> {
    if url.contains('?') || url.contains('#') {
        return Err(Error::InvalidRequest(format!(
            "base_url must not contain a query string or fragment, got {url:?}"
        )));
    }

    // The authority is everything between "scheme://" and the next '/' (or
    // the rest of the string, if there is no path). Userinfo, if present,
    // is a "user:pass@" prefix on it.
    let after_scheme = url.split_once("://").map_or(url.as_str(), |(_, rest)| rest);
    let authority = after_scheme.split('/').next().unwrap_or(after_scheme);
    if authority.contains('@') {
        return Err(Error::InvalidRequest(format!(
            "base_url must not contain userinfo (user:pass@host), got {url:?}"
        )));
    }

    Ok(url.strip_suffix('/').map(str::to_string).unwrap_or(url))
}

/// Rejects an empty or all-whitespace payment id before it is interpolated
/// into a request path.
///
/// Mollie's `GET /v2/payments/{id}` degrades to the **list** endpoint,
/// `GET /v2/payments/`, when `{id}` is empty — silently returning a
/// different resource, with the live API key still attached, instead of the
/// 404 a missing single payment should produce.
fn validate_payment_id(id: &str) -> Result<&str, Error> {
    if id.trim().is_empty() {
        return Err(Error::InvalidRequest(
            "payment id must not be empty".to_string(),
        ));
    }
    Ok(id)
}

/// Percent-encodes a path segment (RFC 3986 unreserved characters pass
/// through unchanged, everything else becomes `%XX`).
///
/// Defensive: `id` is a caller-supplied string (from a webhook payload, a
/// query parameter, ...) that is otherwise interpolated directly into a
/// request path. Without this, a crafted id could inject extra path
/// segments or query parameters into the request this provider sends with
/// its bearer token attached.
fn encode_path_segment(input: &str) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                // `write!` to a `String` never fails.
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    out
}

/// Builds the `metadata` object sent to Mollie by merging a request's
/// caller-supplied metadata with its reference, nested under
/// [`REFERENCE_METADATA_KEY`] — Mollie has no first-class reference field.
/// Returns `Ok(None)` if there is nothing to send.
///
/// # Errors
///
/// Returns [`Error::InvalidRequest`] if `metadata` already uses
/// [`REFERENCE_METADATA_KEY`] as one of its own keys. The two used to be
/// merged flatly rather than actually nested as documented, silently
/// letting the reference clobber a caller value under the same key (or
/// vice versa, depending on iteration order); rejecting the collision
/// up front is the only option that can't silently lose data in either
/// direction.
fn build_metadata(
    reference: Option<&str>,
    metadata: &BTreeMap<String, String>,
) -> Result<Option<serde_json::Value>, Error> {
    if metadata.contains_key(REFERENCE_METADATA_KEY) {
        return Err(Error::InvalidRequest(format!(
            "metadata key {REFERENCE_METADATA_KEY:?} is reserved for CreatePayment::reference"
        )));
    }
    if reference.is_none() && metadata.is_empty() {
        return Ok(None);
    }
    let mut map = serde_json::Map::with_capacity(metadata.len() + 1);
    for (key, value) in metadata {
        map.insert(key.clone(), serde_json::Value::String(value.clone()));
    }
    if let Some(reference) = reference {
        map.insert(
            REFERENCE_METADATA_KEY.to_string(),
            serde_json::Value::String(reference.to_string()),
        );
    }
    Ok(Some(serde_json::Value::Object(map)))
}

/// Inverse of [`build_metadata`]: splits a provider-returned `metadata`
/// value back into a reference and the caller's own metadata map. Never
/// fails — a non-object value or a non-string entry is treated as absent
/// metadata rather than an error, since this is provider-controlled data
/// that must not be able to break decoding of an otherwise-valid payment.
fn parse_metadata(value: Option<serde_json::Value>) -> (Option<String>, BTreeMap<String, String>) {
    let mut metadata = BTreeMap::new();
    let mut reference = None;

    if let Some(serde_json::Value::Object(map)) = value {
        for (key, value) in map {
            let value = match value {
                serde_json::Value::String(s) => s,
                other => other.to_string(),
            };
            if key == REFERENCE_METADATA_KEY {
                reference = Some(value);
            } else {
                metadata.insert(key, value);
            }
        }
    }

    (reference, metadata)
}

fn money_from_wire(amount: &MollieAmount) -> Result<Money, Error> {
    let currency = Currency::new(&amount.currency).map_err(|err| {
        Error::decode(format!(
            "invalid currency {:?} in provider response: {err}",
            amount.currency
        ))
    })?;
    Money::parse_decimal(&amount.value, currency).map_err(|err| {
        Error::decode(format!(
            "invalid amount {:?} in provider response: {err}",
            amount.value
        ))
    })
}

/// Returns `true` if `url` is an absolute `http://` or `https://` URL.
///
/// Mirrors the check `CreatePayment::validate` applies to this crate's own
/// *outbound* `redirect_url`/`webhook_url`, applied here to Mollie's
/// *inbound* `_links.checkout.href` — see the safety note on
/// [`payment_from_wire`] for why the asymmetry matters. A plain prefix
/// check, not a full parse: this crate has no URL-parsing dependency, and a
/// scheme check is enough to reject the realistic hostile case (a
/// `javascript:`, `data:`, or similar non-`http(s)` scheme).
fn is_absolute_http_url(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://")
}

/// Converts a wire payment into a [`Payment`].
///
/// # Security: `checkout_url` scheme
///
/// `_links.checkout.href` is provider-supplied data, copied verbatim into
/// [`Payment::checkout_url`] — which this crate's own README tells
/// integrators to redirect their customer to. A hostile or compromised
/// provider response naming a `javascript:` (or other non-`http(s)`) URL
/// there would otherwise round-trip straight into that redirect unchecked.
/// Rejected here with [`Error::Decode`] before it ever reaches a caller,
/// the same way [`CreatePayment::validate`](crate::payment::CreatePayment::validate)
/// already validates this crate's outbound URLs.
fn payment_from_wire(wire: MolliePayment) -> Result<Payment, Error> {
    let amount = money_from_wire(&wire.amount)?;
    let status = payment_status(&wire.status);
    let checkout_url = wire
        .links
        .and_then(|links| links.checkout)
        .map(|link| link.href);
    // Absent data maps to `None`, never a fabricated placeholder value.
    let (reference, metadata) = parse_metadata(wire.metadata);

    let mut payment = Payment::new(wire.id, status, amount).with_metadata_map(metadata);
    if let Some(url) = checkout_url {
        if !is_absolute_http_url(&url) {
            return Err(Error::decode(format!(
                "provider returned a checkout URL with a non-http(s) scheme: {url:?}"
            )));
        }
        payment = payment.with_checkout_url(url);
    }
    if let Some(reference) = reference {
        payment = payment.with_reference(reference);
    }
    Ok(payment)
}

/// Converts a wire refund into a [`Refund`], falling back to
/// `requested_payment_id` when Mollie's response omits `paymentId` (see
/// [`types::MollieRefund::payment_id`]), and rejecting a response that
/// names a *different* payment outright rather than silently trusting it.
fn refund_from_wire(wire: MollieRefund, requested_payment_id: &str) -> Result<Refund, Error> {
    let amount = money_from_wire(&wire.amount)?;
    let payment_id = match wire.payment_id {
        Some(payment_id) if payment_id == requested_payment_id => payment_id,
        Some(payment_id) => {
            return Err(Error::decode(format!(
                "refunded payment {requested_payment_id:?} but the provider returned a refund \
                 for payment {payment_id:?}"
            )));
        }
        None => requested_payment_id.to_string(),
    };
    Ok(Refund::new(
        wire.id,
        payment_id,
        amount,
        refund_status(&wire.status),
    ))
}

/// Maps Mollie's payment status string to [`PaymentStatus`]. Anything this
/// crate does not recognize is preserved verbatim in
/// [`PaymentStatus::Unknown`] rather than causing a decode failure or being
/// silently discarded.
fn payment_status(raw: &str) -> PaymentStatus {
    match raw {
        "open" => PaymentStatus::Open,
        "pending" => PaymentStatus::Pending,
        "authorized" => PaymentStatus::Authorized,
        "paid" => PaymentStatus::Paid,
        "failed" => PaymentStatus::Failed,
        // Mollie's documented value is the US spelling "canceled"; the UK
        // spelling is accepted defensively in case it is ever sent.
        "canceled" | "cancelled" => PaymentStatus::Cancelled,
        "expired" => PaymentStatus::Expired,
        other => PaymentStatus::Unknown(other.into()),
    }
}

/// Maps Mollie's refund status string to [`RefundStatus`]. See
/// [`payment_status`] for why unrecognized values are preserved rather than
/// rejected.
fn refund_status(raw: &str) -> RefundStatus {
    match raw {
        "queued" => RefundStatus::Queued,
        "pending" => RefundStatus::Pending,
        "processing" => RefundStatus::Processing,
        "refunded" => RefundStatus::Refunded,
        "failed" => RefundStatus::Failed,
        other => RefundStatus::Unknown(other.into()),
    }
}

/// Maps a transport-level [`reqwest::Error`] (one that happened before, or
/// while, reading a response — not an HTTP error status) to [`Error`].
///
/// Always strips the URL first: it can carry sensitive query material (e.g.
/// an id) into whatever logs a consumer's `{:?}` of the resulting `Error`
/// ends up in.
///
/// A *builder* error (an invalid header value, an unparseable URL, ...) is
/// mapped to [`Error::InvalidRequest`], not [`Error::Transport`]: it means
/// the request was never sendable in the first place, so it can never
/// succeed on retry — unlike a genuine transport failure. Checked before
/// [`reqwest::Error::is_timeout`] since a builder error is never a timeout.
fn map_transport_error(err: reqwest::Error) -> Error {
    let err = err.without_url();
    if err.is_builder() {
        Error::InvalidRequest(format!("failed to build the request: {err}"))
    } else if err.is_timeout() {
        Error::Timeout
    } else {
        Error::Transport(Box::new(err))
    }
}

/// Reads a response body without buffering more than [`MAX_RESPONSE_BYTES`].
/// Checked against `Content-Length` up front, and against the actual bytes
/// read as they arrive, since `Content-Length` can be absent or simply
/// wrong.
async fn read_bounded(mut response: reqwest::Response) -> Result<Vec<u8>, Error> {
    if let Some(len) = response.content_length() {
        if len > MAX_RESPONSE_BYTES as u64 {
            return Err(too_large_error(len));
        }
    }

    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(map_transport_error)? {
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(too_large_error(
                (body.len().saturating_add(chunk.len())) as u64,
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn too_large_error(observed_bytes: u64) -> Error {
    Error::decode(format!(
        "response body of at least {observed_bytes} bytes exceeds the \
         {MAX_RESPONSE_BYTES}-byte cap"
    ))
}

async fn decode_json<T: DeserializeOwned>(response: reqwest::Response) -> Result<T, Error> {
    let body = read_bounded(response).await?;
    serde_json::from_slice(&body).map_err(|err| {
        Error::decode(format!("failed to decode provider response as JSON: {err}"))
            .with_raw_body(String::from_utf8_lossy(&body).into_owned())
    })
}

/// Cap on how many characters of a provider-supplied `title`/`detail`
/// string end up in an [`Error::Api`]. Unlike `raw_body`, these two are
/// printed by [`Error`]'s `Display` impl, so an unbounded value here is a
/// direct (if minor) log-noise concern, not just a confidentiality one.
const MAX_ERROR_FIELD_LEN: usize = 200;

/// Strips control characters — including `\n`/`\r`, the classic
/// log-forging vector: a `title` containing one can otherwise inject a fake
/// extra line into anything that prints this error — and truncates to
/// [`MAX_ERROR_FIELD_LEN`] characters.
///
/// Applied to `title` and `detail` before they reach [`Error::Api`]: the
/// only two fields copied out of a provider's response body into something
/// `Error`'s `Display` prints. `raw_body` itself is already kept out of
/// `Display`/`Debug` by `Error` and needs no such treatment.
fn sanitize_error_field(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_ERROR_FIELD_LEN)
        .collect()
}

/// Maps a non-2xx response to the corresponding [`Error`] variant so that
/// [`Error::is_retriable`] is meaningful. The response body is always read
/// (bounded by [`MAX_RESPONSE_BYTES`]) for every non-2xx status *except*
/// `429`: [`Error::RateLimited`] has no `raw_body` field to put it in, so a
/// `429` response body is never read at all — there is nothing to gain from
/// paying for a read whose result could not be attached to anything and
/// would just be dropped. For `401`/`403`/`404` the body *is* read and
/// captured: Mollie's body is usually the only thing that says *why* —
/// "test key against a live payment" versus an inactive profile for a
/// `403`, or a misconfigured `base_url` for a `404` whose status alone is
/// otherwise maximally misleading. That body is reachable via
/// [`Error::raw_body`], never via `Display`/`Debug`.
///
/// - `429` -> [`Error::rate_limited`], with `retry_after` parsed from the
///   `Retry-After` header when present (retriable). No body is read.
/// - `401`/`403` -> [`Error::unauthorized`], `404` -> [`Error::not_found`],
///   each carrying the body. These keep their own variants rather than
///   collapsing into [`Error::api`], so that a consumer matching on
///   `Error::Unauthorized` — the obvious way to detect a bad API key —
///   actually fires.
/// - everything else (`422` and other `4xx`, and `5xx`) -> [`Error::api`],
///   retriable only for `5xx`. When Mollie's typed error body decodes, its
///   `title`/`detail` are attached after [`sanitize_error_field`] strips
///   control characters and bounds their length. Both are kept out of
///   `Display`/`Debug` — see [`Error::title`]/[`Error::detail`].
async fn build_error_response(response: reqwest::Response) -> Error {
    let status = response.status();
    let retry_after = parse_retry_after(response.headers());

    // Handled before anything reads the body: a 429 response body has
    // nowhere to go (see the doc comment above), so it is left unread on
    // the wire rather than buffered and immediately discarded.
    if status.as_u16() == 429 {
        return Error::rate_limited(retry_after);
    }

    let raw_body = read_bounded(response)
        .await
        .ok()
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());

    let dedicated = match status.as_u16() {
        401 | 403 => Some(Error::unauthorized()),
        404 => Some(Error::not_found()),
        _ => None,
    };
    if let Some(mut err) = dedicated {
        if let Some(raw_body) = raw_body {
            err = err.with_raw_body(raw_body);
        }
        return err;
    }

    // Only parsed once the response is known to need it: neither the `429`
    // nor the `401`/`403`/`404` paths above use the typed error body, so
    // deserializing it for them would be wasted work.
    let parsed: Option<MollieErrorBody> = raw_body
        .as_deref()
        .and_then(|body| serde_json::from_str(body).ok());

    let title = parsed
        .as_ref()
        .and_then(|body| body.title.as_deref())
        .map(sanitize_error_field)
        .unwrap_or_else(|| {
            status
                .canonical_reason()
                .unwrap_or("unknown provider error")
                .to_string()
        });

    let mut err = Error::api(status.as_u16(), title);
    if let Some(code) = parsed.as_ref().and_then(|body| body.field.clone()) {
        err = err.with_code(code);
    }
    if let Some(detail) = parsed.and_then(|body| body.detail) {
        err = err.with_detail(sanitize_error_field(&detail));
    }
    if let Some(raw_body) = raw_body {
        err = err.with_raw_body(raw_body);
    }
    err
}

/// Cap applied to a parsed `Retry-After` value. Mollie's real rate-limit
/// windows are seconds to low minutes; without a cap, a malformed or
/// hostile response (`Retry-After: 999999999999`) would otherwise produce a
/// multi-millennium [`Duration`] that a caller sleeping on it would never
/// wake up from.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(300);

/// Parses a `Retry-After` header as a whole number of delta-seconds, which
/// is the form Mollie's rate-limit responses use, clamped to
/// [`MAX_RETRY_AFTER`]. The HTTP-date form is not handled — a `None` here
/// just means the caller falls back to its own retry/backoff policy.
fn parse_retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    headers
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(|secs| Duration::from_secs(secs).min(MAX_RETRY_AFTER))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

    use super::*;
    use crate::payment::RefundStatus;

    fn test_provider(server: &MockServer) -> MollieProvider {
        MollieProvider::builder("test_key")
            .insecure_base_url_for_testing(server.uri())
            .build()
            .unwrap()
    }

    fn eur(minor: i64) -> Money {
        Money::from_minor(minor, Currency::EUR)
    }

    fn mollie_payment_json(
        id: &str,
        status: &str,
        value: &str,
        currency: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "status": status,
            "amount": {"currency": currency, "value": value},
            "_links": {"checkout": {"href": "https://mollie.example/pay/1"}},
        })
    }

    // --- construction: no panics, redaction, clone ---

    #[test]
    fn new_never_panics_and_defaults_to_the_mollie_api() {
        let provider = MollieProvider::new("test_key").unwrap();
        assert!(format!("{provider:?}").contains("api.mollie.com"));
    }

    #[test]
    fn provider_is_cheaply_cloneable() {
        let provider = MollieProvider::new("test_key").unwrap();
        let cloned = provider.clone();
        assert_eq!(format!("{provider:?}"), format!("{cloned:?}"));
    }

    #[test]
    fn base_url_rejects_non_https_scheme() {
        let err = MollieProvider::builder("key")
            .base_url("http://api.mollie.com/v2")
            .build()
            .unwrap_err();
        assert!(matches!(err, Error::InvalidRequest(_)));
    }

    #[test]
    fn base_url_accepts_https_scheme() {
        let provider = MollieProvider::builder("key")
            .base_url("https://api.mollie.com/v2")
            .build();
        assert!(provider.is_ok());
    }

    #[test]
    fn base_url_rejects_userinfo() {
        let err = MollieProvider::builder("key")
            .base_url("https://api.mollie.com@evil.example/v2")
            .build()
            .unwrap_err();
        assert!(matches!(err, Error::InvalidRequest(_)));
    }

    #[test]
    fn base_url_rejects_query_string() {
        let err = MollieProvider::builder("key")
            .base_url("https://api.mollie.com/v2?x=1")
            .build()
            .unwrap_err();
        assert!(matches!(err, Error::InvalidRequest(_)));
    }

    #[test]
    fn base_url_rejects_fragment() {
        let err = MollieProvider::builder("key")
            .base_url("https://api.mollie.com/v2#frag")
            .build()
            .unwrap_err();
        assert!(matches!(err, Error::InvalidRequest(_)));
    }

    #[tokio::test]
    async fn base_url_trailing_slash_does_not_double_up_the_path() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/payments/tr_1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(mollie_payment_json("tr_1", "open", "1.00", "EUR")),
            )
            .mount(&server)
            .await;

        let provider = MollieProvider::builder("test_key")
            .insecure_base_url_for_testing(format!("{}/", server.uri()))
            .build()
            .unwrap();
        let payment = provider.get_payment("tr_1").await.unwrap();
        assert_eq!(payment.id, "tr_1");
    }

    #[test]
    fn build_never_panics_on_an_api_key_with_invalid_header_bytes() {
        let err = MollieProvider::new("bad\nkey").unwrap_err();
        assert!(matches!(err, Error::InvalidRequest(_)));
    }

    #[test]
    fn debug_never_contains_the_api_key() {
        let provider = MollieProvider::new("sk_live_super_secret_key").unwrap();
        let debug = format!("{provider:?}");
        assert!(!debug.contains("sk_live_super_secret_key"));
    }

    #[tokio::test]
    async fn api_key_never_appears_in_an_error_from_an_unreachable_host() {
        let provider = MollieProvider::builder("sk_live_super_secret_key")
            .insecure_base_url_for_testing("http://127.0.0.1:1")
            .build()
            .unwrap();
        let err = provider.get_payment("tr_1").await.unwrap_err();
        assert!(!format!("{err:?}").contains("sk_live_super_secret_key"));
        assert!(!format!("{err}").contains("sk_live_super_secret_key"));
    }

    // --- redirects ---

    #[tokio::test]
    async fn redirects_are_not_followed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/payments/tr_1"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", "http://example.invalid/elsewhere"),
            )
            .mount(&server)
            .await;

        let provider = test_provider(&server);
        let err = provider.get_payment("tr_1").await.unwrap_err();
        assert!(matches!(err, Error::Api { status: 302, .. }));
    }

    // --- bounded reads ---

    #[tokio::test]
    async fn oversized_response_body_is_rejected() {
        let server = MockServer::start().await;
        let huge = "x".repeat(2 * MAX_RESPONSE_BYTES);
        Mock::given(method("GET"))
            .and(path("/payments/tr_1"))
            .respond_with(ResponseTemplate::new(200).set_body_string(huge))
            .mount(&server)
            .await;

        let provider = test_provider(&server);
        let err = provider.get_payment("tr_1").await.unwrap_err();
        assert!(matches!(err, Error::Decode { .. }));
    }

    // --- empty/blank ids ---

    #[tokio::test]
    async fn get_payment_rejects_an_empty_id_without_sending_a_request() {
        let server = MockServer::start().await;
        // No mock mounted: if a request were sent despite the empty id,
        // wiremock's default 404 would surface as `Error::Api` instead of
        // `Error::InvalidRequest`.
        let provider = test_provider(&server);
        let err = provider.get_payment("").await.unwrap_err();
        assert!(matches!(err, Error::InvalidRequest(_)));
    }

    #[tokio::test]
    async fn get_payment_rejects_a_blank_id() {
        let server = MockServer::start().await;
        let provider = test_provider(&server);
        let err = provider.get_payment("   ").await.unwrap_err();
        assert!(matches!(err, Error::InvalidRequest(_)));
    }

    #[tokio::test]
    async fn cancel_payment_rejects_an_empty_id() {
        let server = MockServer::start().await;
        let provider = test_provider(&server);
        let err = provider.cancel_payment("").await.unwrap_err();
        assert!(matches!(err, Error::InvalidRequest(_)));
    }

    #[tokio::test]
    async fn refund_rejects_an_empty_id() {
        let server = MockServer::start().await;
        let provider = test_provider(&server);
        let err = provider
            .refund("", RefundRequest::new(eur(500)))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidRequest(_)));
    }

    // --- get_payment ---

    #[tokio::test]
    async fn get_payment_maps_status_amount_checkout_url_reference_and_metadata() {
        let server = MockServer::start().await;
        let body = serde_json::json!({
            "id": "tr_1",
            "status": "paid",
            "amount": {"currency": "EUR", "value": "12.34"},
            "metadata": {"paykit_reference": "order-42", "channel": "web"},
            "_links": {"checkout": {"href": "https://mollie.example/pay/tr_1"}},
        });
        Mock::given(method("GET"))
            .and(path("/payments/tr_1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let provider = test_provider(&server);
        let payment = provider.get_payment("tr_1").await.unwrap();

        assert_eq!(payment.id, "tr_1");
        assert_eq!(payment.status, PaymentStatus::Paid);
        assert_eq!(payment.amount, eur(1234));
        assert_eq!(
            payment.checkout_url.as_deref(),
            Some("https://mollie.example/pay/tr_1")
        );
        assert_eq!(payment.reference.as_deref(), Some("order-42"));
        assert_eq!(
            payment.metadata.get("channel").map(String::as_str),
            Some("web")
        );
        assert!(!payment.metadata.contains_key("paykit_reference"));
    }

    #[tokio::test]
    async fn get_payment_rejects_a_checkout_url_with_a_non_http_scheme() {
        let server = MockServer::start().await;
        let body = serde_json::json!({
            "id": "tr_1",
            "status": "open",
            "amount": {"currency": "EUR", "value": "1.00"},
            "_links": {"checkout": {"href": "javascript:alert(1)"}},
        });
        Mock::given(method("GET"))
            .and(path("/payments/tr_1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let provider = test_provider(&server);
        let err = provider.get_payment("tr_1").await.unwrap_err();
        assert!(matches!(err, Error::Decode { .. }));
    }

    #[tokio::test]
    async fn get_payment_accepts_a_plain_http_checkout_url() {
        let server = MockServer::start().await;
        let body = serde_json::json!({
            "id": "tr_1",
            "status": "open",
            "amount": {"currency": "EUR", "value": "1.00"},
            "_links": {"checkout": {"href": "http://mollie.example/pay/tr_1"}},
        });
        Mock::given(method("GET"))
            .and(path("/payments/tr_1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let provider = test_provider(&server);
        let payment = provider.get_payment("tr_1").await.unwrap();
        assert_eq!(
            payment.checkout_url.as_deref(),
            Some("http://mollie.example/pay/tr_1")
        );
    }

    #[tokio::test]
    async fn absent_metadata_and_links_map_to_none_never_fabricated() {
        let server = MockServer::start().await;
        let body = serde_json::json!({
            "id": "tr_1",
            "status": "open",
            "amount": {"currency": "EUR", "value": "1.00"},
        });
        Mock::given(method("GET"))
            .and(path("/payments/tr_1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let provider = test_provider(&server);
        let payment = provider.get_payment("tr_1").await.unwrap();
        assert_eq!(payment.reference, None);
        assert_eq!(payment.checkout_url, None);
        assert!(payment.metadata.is_empty());
    }

    #[tokio::test]
    async fn get_payment_rejects_a_mismatched_id_in_the_response() {
        let server = MockServer::start().await;
        let body = serde_json::json!({
            "id": "tr_other",
            "status": "open",
            "amount": {"currency": "EUR", "value": "1.00"},
        });
        Mock::given(method("GET"))
            .and(path("/payments/tr_1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let provider = test_provider(&server);
        let err = provider.get_payment("tr_1").await.unwrap_err();
        assert!(matches!(err, Error::Decode { .. }));
    }

    #[tokio::test]
    async fn unknown_payment_status_is_preserved_verbatim() {
        let server = MockServer::start().await;
        let body = serde_json::json!({
            "id": "tr_1",
            "status": "a_future_status_mollie_invented",
            "amount": {"currency": "EUR", "value": "1.00"},
        });
        Mock::given(method("GET"))
            .and(path("/payments/tr_1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let provider = test_provider(&server);
        let payment = provider.get_payment("tr_1").await.unwrap();
        match payment.status {
            PaymentStatus::Unknown(raw) => assert_eq!(&*raw, "a_future_status_mollie_invented"),
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn payment_id_is_percent_encoded_in_the_request_path() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/payments/weird%20id%2Fwith%20slash"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(mollie_payment_json(
                    "weird id/with slash",
                    "open",
                    "1.00",
                    "EUR",
                )),
            )
            .mount(&server)
            .await;

        let provider = test_provider(&server);
        let payment = provider.get_payment("weird id/with slash").await.unwrap();
        assert_eq!(payment.id, "weird id/with slash");
    }

    // --- error mapping ---

    #[tokio::test]
    async fn unauthorized_maps_to_the_unauthorized_variant_and_captures_the_body() {
        let server = MockServer::start().await;
        let body = serde_json::json!({
            "title": "Unauthorized",
            "detail": "test key used for a live payment",
        });
        Mock::given(method("GET"))
            .and(path("/payments/tr_1"))
            .respond_with(ResponseTemplate::new(401).set_body_json(&body))
            .mount(&server)
            .await;
        let provider = test_provider(&server);
        let err = provider.get_payment("tr_1").await.unwrap_err();
        assert!(matches!(err, Error::Unauthorized { .. }));
        assert!(!err.is_retriable());
        assert!(err.raw_body().unwrap().contains("live payment"));
    }

    #[tokio::test]
    async fn forbidden_also_maps_to_the_unauthorized_variant() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/payments/tr_1"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        let provider = test_provider(&server);
        let err = provider.get_payment("tr_1").await.unwrap_err();
        assert!(matches!(err, Error::Unauthorized { .. }));
        assert!(!err.is_retriable());
    }

    #[tokio::test]
    async fn not_found_maps_to_the_not_found_variant_and_captures_the_body() {
        let server = MockServer::start().await;
        let body = serde_json::json!({"title": "Not Found", "detail": "No payment exists with token tr_1."});
        Mock::given(method("GET"))
            .and(path("/payments/tr_1"))
            .respond_with(ResponseTemplate::new(404).set_body_json(&body))
            .mount(&server)
            .await;
        let provider = test_provider(&server);
        let err = provider.get_payment("tr_1").await.unwrap_err();
        assert!(matches!(err, Error::NotFound { .. }));
        assert!(!err.is_retriable());
        assert!(err.raw_body().unwrap().contains("No payment exists"));
    }

    #[tokio::test]
    async fn unprocessable_entity_maps_to_api_with_field_as_code_and_is_not_retriable() {
        let server = MockServer::start().await;
        let body = serde_json::json!({
            "status": 422,
            "title": "Unprocessable Entity",
            "detail": "amount is required",
            "field": "amount",
        });
        Mock::given(method("POST"))
            .and(path("/payments"))
            .respond_with(ResponseTemplate::new(422).set_body_json(body))
            .mount(&server)
            .await;

        let provider = test_provider(&server);
        let req = CreatePayment::new(eur(1000), "order", "https://shop.example/return");
        let err = provider.create_payment(req).await.unwrap_err();
        match &err {
            Error::Api {
                status,
                code,
                title,
                detail,
                ..
            } => {
                assert_eq!(*status, 422);
                assert_eq!(code.as_deref(), Some("amount"));
                assert_eq!(title, "Unprocessable Entity");
                assert_eq!(detail.as_deref(), Some("amount is required"));
            }
            other => panic!("expected Api, got {other:?}"),
        }
        assert!(!err.is_retriable());
    }

    #[tokio::test]
    async fn error_title_and_detail_are_sanitized_of_control_characters() {
        let server = MockServer::start().await;
        let body = serde_json::json!({
            "title": "Bad\r\nRequest: forged log line",
            "detail": "some\ndetail\twith control chars",
        });
        Mock::given(method("GET"))
            .and(path("/payments/tr_1"))
            .respond_with(ResponseTemplate::new(400).set_body_json(&body))
            .mount(&server)
            .await;
        let provider = test_provider(&server);
        let err = provider.get_payment("tr_1").await.unwrap_err();
        match &err {
            Error::Api { title, detail, .. } => {
                assert!(!title.contains('\n') && !title.contains('\r'));
                let detail = detail.as_deref().unwrap_or_default();
                assert!(!detail.contains('\n') && !detail.contains('\t'));
            }
            other => panic!("expected Api, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rate_limited_parses_retry_after_seconds_and_is_retriable() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/payments/tr_1"))
            .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "30"))
            .mount(&server)
            .await;
        let provider = test_provider(&server);
        let err = provider.get_payment("tr_1").await.unwrap_err();
        match &err {
            Error::RateLimited { retry_after, .. } => {
                assert_eq!(*retry_after, Some(Duration::from_secs(30)));
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
        assert!(err.is_retriable());
    }

    #[tokio::test]
    async fn rate_limited_clamps_an_absurd_retry_after_value() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/payments/tr_1"))
            .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "999999999999"))
            .mount(&server)
            .await;
        let provider = test_provider(&server);
        let err = provider.get_payment("tr_1").await.unwrap_err();
        match &err {
            Error::RateLimited { retry_after, .. } => {
                assert_eq!(*retry_after, Some(MAX_RETRY_AFTER));
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rate_limited_never_captures_a_body_even_when_the_provider_sends_one() {
        // `Error::RateLimited` has no `raw_body` field, so a 429 response
        // body must never be read at all, not merely dropped after reading.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/payments/tr_1"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("Retry-After", "5")
                    .set_body_json(serde_json::json!({"title": "Rate limit exceeded"})),
            )
            .mount(&server)
            .await;
        let provider = test_provider(&server);
        let err = provider.get_payment("tr_1").await.unwrap_err();
        assert!(matches!(err, Error::RateLimited { .. }));
        assert_eq!(err.raw_body(), None);
    }

    #[tokio::test]
    async fn rate_limited_does_not_choke_on_an_oversized_body() {
        // Proof that the body genuinely goes unread for a 429: an oversized
        // body would fail with `Error::Decode` (see
        // `oversized_response_body_is_rejected`) for any status this crate
        // actually reads the body for.
        let server = MockServer::start().await;
        let huge = "x".repeat(2 * MAX_RESPONSE_BYTES);
        Mock::given(method("GET"))
            .and(path("/payments/tr_1"))
            .respond_with(
                ResponseTemplate::new(429)
                    .insert_header("Retry-After", "5")
                    .set_body_string(huge),
            )
            .mount(&server)
            .await;
        let provider = test_provider(&server);
        let err = provider.get_payment("tr_1").await.unwrap_err();
        assert!(matches!(err, Error::RateLimited { .. }));
    }

    #[tokio::test]
    async fn server_error_maps_to_api_and_is_retriable() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/payments/tr_1"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let provider = test_provider(&server);
        let err = provider.get_payment("tr_1").await.unwrap_err();
        assert!(matches!(err, Error::Api { status: 503, .. }));
        assert!(err.is_retriable());
    }

    #[tokio::test]
    async fn api_error_raw_body_is_reachable_but_never_in_display() {
        let server = MockServer::start().await;
        let body = serde_json::json!({
            "title": "Bad Request",
            "detail": "contains a card_number that must never be logged by default",
        });
        Mock::given(method("GET"))
            .and(path("/payments/tr_1"))
            .respond_with(ResponseTemplate::new(400).set_body_json(&body))
            .mount(&server)
            .await;
        let provider = test_provider(&server);
        let err = provider.get_payment("tr_1").await.unwrap_err();
        assert!(err.raw_body().unwrap().contains("card_number"));
        assert!(!format!("{err}").contains("card_number"));
    }

    // --- create_payment ---

    #[tokio::test]
    async fn create_payment_validates_before_sending_anything() {
        // No mock mounted: if the request were sent despite failing
        // validation, wiremock's default 404 response would surface as
        // `Error::Api` instead of `Error::InvalidRequest`.
        let server = MockServer::start().await;
        let provider = test_provider(&server);
        let req = CreatePayment::new(eur(1000), "order", "/relative-not-absolute");
        let err = provider.create_payment(req).await.unwrap_err();
        assert!(matches!(err, Error::InvalidRequest(_)));
    }

    #[tokio::test]
    async fn create_payment_sends_amount_redirect_url_and_metadata_with_reference_nested() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/payments"))
            .and(body_partial_json(serde_json::json!({
                "amount": {"currency": "EUR", "value": "10.00"},
                "redirectUrl": "https://shop.example/return",
                "metadata": {"channel": "web", "paykit_reference": "order-42"},
            })))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(mollie_payment_json("tr_1", "open", "10.00", "EUR")),
            )
            .mount(&server)
            .await;

        let provider = test_provider(&server);
        let req = CreatePayment::new(eur(1000), "order #1", "https://shop.example/return")
            .with_reference("order-42")
            .with_metadata_entry("channel", "web");
        let payment = provider.create_payment(req).await.unwrap();
        assert_eq!(payment.status, PaymentStatus::Open);
    }

    #[tokio::test]
    async fn create_payment_rejects_a_reserved_metadata_key() {
        let server = MockServer::start().await;
        let provider = test_provider(&server);
        let req = CreatePayment::new(eur(1000), "order", "https://shop.example/return")
            .with_metadata_entry(REFERENCE_METADATA_KEY, "user-supplied");
        let err = provider.create_payment(req).await.unwrap_err();
        assert!(matches!(err, Error::InvalidRequest(_)));
    }

    #[tokio::test]
    async fn create_payment_rejects_an_amount_mismatch_echoed_by_the_provider() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/payments"))
            .respond_with(
                ResponseTemplate::new(201)
                    // Provider echoes back a different amount than requested.
                    .set_body_json(mollie_payment_json("tr_1", "open", "5.00", "EUR")),
            )
            .mount(&server)
            .await;

        let provider = test_provider(&server);
        let req = CreatePayment::new(eur(1000), "order", "https://shop.example/return");
        let err = provider.create_payment(req).await.unwrap_err();
        assert!(matches!(err, Error::Decode { .. }));
    }

    #[tokio::test]
    async fn create_payment_encodes_zero_decimal_currencies_without_dividing_by_100() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/payments"))
            .and(body_partial_json(
                serde_json::json!({"amount": {"currency": "JPY", "value": "1000"}}),
            ))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(mollie_payment_json("tr_jpy", "open", "1000", "JPY")),
            )
            .mount(&server)
            .await;

        let provider = test_provider(&server);
        let req = CreatePayment::new(
            Money::from_minor(1000, Currency::JPY),
            "order",
            "https://shop.example/return",
        );
        let payment = provider.create_payment(req).await.unwrap();
        assert_eq!(payment.amount, Money::from_minor(1000, Currency::JPY));
    }

    /// Captures the value of a header on every matching request, always
    /// matching so the mock never fails to respond.
    struct CaptureHeader {
        name: &'static str,
        seen: Arc<Mutex<Vec<String>>>,
    }

    impl Match for CaptureHeader {
        fn matches(&self, request: &Request) -> bool {
            if let Some(value) = request.headers.get(self.name).and_then(|v| v.to_str().ok()) {
                self.seen.lock().unwrap().push(value.to_string());
            }
            true
        }
    }

    #[tokio::test]
    async fn create_payment_reuses_the_requests_idempotency_key_on_retry() {
        let server = MockServer::start().await;
        let seen = Arc::new(Mutex::new(Vec::new()));
        Mock::given(method("POST"))
            .and(path("/payments"))
            .and(CaptureHeader {
                name: "idempotency-key",
                seen: Arc::clone(&seen),
            })
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(mollie_payment_json("tr_1", "open", "10.00", "EUR")),
            )
            .mount(&server)
            .await;

        let provider = test_provider(&server);
        let req = CreatePayment::new(eur(1000), "order", "https://shop.example/return");
        // Simulates a caller retrying the exact same request after, say, a
        // timeout — the entire point of an idempotency key. Generating a
        // fresh one per call here (rather than reading it from `req`) would
        // make Mollie treat the retry as a brand new payment.
        provider.create_payment(req.clone()).await.unwrap();
        provider.create_payment(req.clone()).await.unwrap();

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(
            seen[0], seen[1],
            "a retried request must reuse the same idempotency key, not a fresh one"
        );
    }

    #[tokio::test]
    async fn create_payment_uses_the_caller_supplied_idempotency_key_when_present() {
        let server = MockServer::start().await;
        let seen = Arc::new(Mutex::new(Vec::new()));
        Mock::given(method("POST"))
            .and(path("/payments"))
            .and(CaptureHeader {
                name: "idempotency-key",
                seen: Arc::clone(&seen),
            })
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(mollie_payment_json("tr_1", "open", "10.00", "EUR")),
            )
            .mount(&server)
            .await;

        let provider = test_provider(&server);
        let req = CreatePayment::new(eur(1000), "order", "https://shop.example/return")
            .with_idempotency_key("caller-chosen-key");
        provider.create_payment(req).await.unwrap();

        assert_eq!(seen.lock().unwrap().as_slice(), ["caller-chosen-key"]);
    }

    // --- cancel_payment ---

    #[tokio::test]
    async fn cancel_payment_returns_the_decoded_payment_not_a_bare_ack() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/payments/tr_1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(mollie_payment_json("tr_1", "canceled", "5.00", "EUR")),
            )
            .mount(&server)
            .await;
        let provider = test_provider(&server);
        let payment = provider.cancel_payment("tr_1").await.unwrap();
        assert_eq!(payment.status, PaymentStatus::Cancelled);
        assert_eq!(payment.amount, eur(500));
    }

    #[tokio::test]
    async fn cancel_payment_rejects_a_mismatched_id_in_the_response() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/payments/tr_1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(mollie_payment_json("tr_other", "canceled", "5.00", "EUR")),
            )
            .mount(&server)
            .await;
        let provider = test_provider(&server);
        let err = provider.cancel_payment("tr_1").await.unwrap_err();
        assert!(matches!(err, Error::Decode { .. }));
    }

    // --- refund ---

    #[tokio::test]
    async fn refund_always_sends_amount_and_returns_the_decoded_refund() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/payments/tr_1/refunds"))
            .and(body_partial_json(
                serde_json::json!({"amount": {"currency": "EUR", "value": "5.00"}}),
            ))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "re_1",
                "paymentId": "tr_1",
                "amount": {"currency": "EUR", "value": "5.00"},
                "status": "pending",
            })))
            .mount(&server)
            .await;

        let provider = test_provider(&server);
        let refund = provider
            .refund("tr_1", RefundRequest::new(eur(500)))
            .await
            .unwrap();
        assert_eq!(refund.id, "re_1");
        assert_eq!(refund.payment_id, "tr_1");
        assert_eq!(refund.amount, eur(500));
        assert_eq!(refund.status, RefundStatus::Pending);
    }

    #[tokio::test]
    async fn refund_falls_back_to_the_requested_payment_id_when_the_response_omits_it() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/payments/tr_1/refunds"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "re_1",
                "amount": {"currency": "EUR", "value": "5.00"},
                "status": "queued",
            })))
            .mount(&server)
            .await;

        let provider = test_provider(&server);
        let refund = provider
            .refund("tr_1", RefundRequest::new(eur(500)))
            .await
            .unwrap();
        assert_eq!(refund.payment_id, "tr_1");
    }

    #[tokio::test]
    async fn refund_rejects_a_mismatched_payment_id_in_the_response() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/payments/tr_1/refunds"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "re_1",
                "paymentId": "tr_other",
                "amount": {"currency": "EUR", "value": "5.00"},
                "status": "queued",
            })))
            .mount(&server)
            .await;

        let provider = test_provider(&server);
        let err = provider
            .refund("tr_1", RefundRequest::new(eur(500)))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Decode { .. }));
    }

    fn mollie_refund_response() -> serde_json::Value {
        serde_json::json!({
            "id": "re_1",
            "paymentId": "tr_1",
            "amount": {"currency": "EUR", "value": "5.00"},
            "status": "pending",
        })
    }

    #[tokio::test]
    async fn refund_always_sends_the_idempotency_key_header() {
        let server = MockServer::start().await;
        let seen = Arc::new(Mutex::new(Vec::new()));
        Mock::given(method("POST"))
            .and(path("/payments/tr_1/refunds"))
            .and(CaptureHeader {
                name: "idempotency-key",
                seen: Arc::clone(&seen),
            })
            .respond_with(ResponseTemplate::new(201).set_body_json(mollie_refund_response()))
            .mount(&server)
            .await;

        let provider = test_provider(&server);
        // No `with_idempotency_key` call: the header must still be sent,
        // since `RefundRequest::new` generates one eagerly.
        provider
            .refund("tr_1", RefundRequest::new(eur(500)))
            .await
            .unwrap();

        assert_eq!(
            seen.lock().unwrap().len(),
            1,
            "expected exactly one request, with the Idempotency-Key header present"
        );
    }

    #[tokio::test]
    async fn refund_reuses_the_same_requests_idempotency_key_across_retries() {
        let server = MockServer::start().await;
        let seen = Arc::new(Mutex::new(Vec::new()));
        Mock::given(method("POST"))
            .and(path("/payments/tr_1/refunds"))
            .and(CaptureHeader {
                name: "idempotency-key",
                seen: Arc::clone(&seen),
            })
            .respond_with(ResponseTemplate::new(201).set_body_json(mollie_refund_response()))
            .mount(&server)
            .await;

        let provider = test_provider(&server);
        // Simulates a caller retrying the exact same `RefundRequest` value
        // after, say, `Error::Timeout` — the protocol `Error::is_retriable`
        // invites. This must not create a second, duplicate refund.
        let req = RefundRequest::new(eur(500));
        provider.refund("tr_1", req.clone()).await.unwrap();
        provider.refund("tr_1", req).await.unwrap();

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(
            seen[0], seen[1],
            "retrying the same RefundRequest value must reuse the same idempotency key"
        );
    }

    #[tokio::test]
    async fn refund_uses_different_idempotency_keys_for_separately_constructed_requests() {
        let server = MockServer::start().await;
        let seen = Arc::new(Mutex::new(Vec::new()));
        Mock::given(method("POST"))
            .and(path("/payments/tr_1/refunds"))
            .and(CaptureHeader {
                name: "idempotency-key",
                seen: Arc::clone(&seen),
            })
            .respond_with(ResponseTemplate::new(201).set_body_json(mollie_refund_response()))
            .mount(&server)
            .await;

        let provider = test_provider(&server);
        provider
            .refund("tr_1", RefundRequest::new(eur(500)))
            .await
            .unwrap();
        provider
            .refund("tr_1", RefundRequest::new(eur(500)))
            .await
            .unwrap();

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert_ne!(
            seen[0], seen[1],
            "two separately constructed RefundRequests must not share an idempotency key"
        );
    }

    // --- fetch_verified / VerifiedPayment (default trait behavior, exercised via the
    // real Mollie wire mapping) ---

    #[tokio::test]
    async fn fetch_verified_returns_verified_payment_on_matching_amount_and_paid_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/payments/tr_1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(mollie_payment_json("tr_1", "paid", "10.00", "EUR")),
            )
            .mount(&server)
            .await;
        let provider = test_provider(&server);
        let verified = provider.fetch_verified("tr_1", eur(1000)).await.unwrap();
        assert_eq!(verified.payment().status, PaymentStatus::Paid);
        let payment = verified.into_payment();
        assert_eq!(payment.amount, eur(1000));
    }

    #[tokio::test]
    async fn fetch_verified_rejects_amount_mismatch() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/payments/tr_1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(mollie_payment_json("tr_1", "paid", "9.99", "EUR")),
            )
            .mount(&server)
            .await;
        let provider = test_provider(&server);
        let err = provider
            .fetch_verified("tr_1", eur(1000))
            .await
            .unwrap_err();
        match err {
            Error::AmountMismatch { expected, actual } => {
                assert_eq!(expected, eur(1000));
                assert_eq!(actual, eur(999));
            }
            other => panic!("expected AmountMismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fetch_verified_rejects_currency_mismatch_even_with_equal_minor_units() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/payments/tr_1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(mollie_payment_json("tr_1", "paid", "10.00", "USD")),
            )
            .mount(&server)
            .await;
        let provider = test_provider(&server);
        let err = provider
            .fetch_verified("tr_1", eur(1000))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::AmountMismatch { .. }));
    }

    #[tokio::test]
    async fn fetch_verified_rejects_a_matching_amount_that_is_not_paid() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/payments/tr_1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(mollie_payment_json("tr_1", "open", "10.00", "EUR")),
            )
            .mount(&server)
            .await;
        let provider = test_provider(&server);
        let err = provider
            .fetch_verified("tr_1", eur(1000))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::NotPaid { .. }));
    }

    // --- pure helper functions ---

    #[test]
    fn encode_path_segment_leaves_unreserved_chars_untouched() {
        assert_eq!(encode_path_segment("tr_ABC123-._~"), "tr_ABC123-._~");
    }

    #[test]
    fn encode_path_segment_escapes_everything_else() {
        assert_eq!(encode_path_segment("a b/c"), "a%20b%2Fc");
    }

    #[test]
    fn is_absolute_http_url_accepts_http_and_https() {
        assert!(is_absolute_http_url("http://mollie.example/pay/1"));
        assert!(is_absolute_http_url("https://mollie.example/pay/1"));
    }

    #[test]
    fn is_absolute_http_url_rejects_other_schemes_and_relative_values() {
        assert!(!is_absolute_http_url("javascript:alert(1)"));
        assert!(!is_absolute_http_url(
            "data:text/html,<script>alert(1)</script>"
        ));
        assert!(!is_absolute_http_url("/relative/path"));
        assert!(!is_absolute_http_url(""));
    }

    #[test]
    fn map_transport_error_maps_a_builder_error_to_invalid_request_not_transport() {
        let err = reqwest::Client::new()
            .get("not a valid url")
            .build()
            .unwrap_err();
        assert!(err.is_builder());
        let mapped = map_transport_error(err);
        assert!(matches!(mapped, Error::InvalidRequest(_)));
        assert!(!mapped.is_retriable());
    }

    #[test]
    fn build_and_parse_metadata_round_trips_reference_and_user_metadata() {
        let mut metadata = BTreeMap::new();
        metadata.insert("channel".to_string(), "web".to_string());
        let value = build_metadata(Some("order-42"), &metadata)
            .unwrap()
            .unwrap();
        let (reference, parsed) = parse_metadata(Some(value));
        assert_eq!(reference.as_deref(), Some("order-42"));
        assert_eq!(parsed.get("channel").map(String::as_str), Some("web"));
        assert!(!parsed.contains_key(REFERENCE_METADATA_KEY));
    }

    #[test]
    fn build_metadata_returns_none_when_there_is_nothing_to_send() {
        assert_eq!(build_metadata(None, &BTreeMap::new()).unwrap(), None);
    }

    #[test]
    fn build_metadata_rejects_a_caller_supplied_reserved_key() {
        let mut metadata = BTreeMap::new();
        metadata.insert(REFERENCE_METADATA_KEY.to_string(), "user-value".to_string());
        let err = build_metadata(Some("order-42"), &metadata).unwrap_err();
        assert!(matches!(err, Error::InvalidRequest(_)));
    }

    #[test]
    fn parse_metadata_of_none_is_empty() {
        let (reference, metadata) = parse_metadata(None);
        assert_eq!(reference, None);
        assert!(metadata.is_empty());
    }

    #[test]
    fn money_from_wire_rejects_invalid_currency() {
        let err = money_from_wire(&MollieAmount {
            currency: "EU".into(),
            value: "1.00".into(),
        })
        .unwrap_err();
        assert!(matches!(err, Error::Decode { .. }));
    }

    #[test]
    fn money_from_wire_rejects_invalid_amount() {
        let err = money_from_wire(&MollieAmount {
            currency: "EUR".into(),
            value: "abc".into(),
        })
        .unwrap_err();
        assert!(matches!(err, Error::Decode { .. }));
    }

    #[test]
    fn payment_status_preserves_unrecognized_values() {
        match payment_status("a_future_status") {
            PaymentStatus::Unknown(raw) => assert_eq!(&*raw, "a_future_status"),
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn payment_status_accepts_both_cancelled_spellings() {
        assert_eq!(payment_status("canceled"), PaymentStatus::Cancelled);
        assert_eq!(payment_status("cancelled"), PaymentStatus::Cancelled);
    }

    #[test]
    fn refund_status_preserves_unrecognized_values() {
        match refund_status("a_future_status") {
            RefundStatus::Unknown(raw) => assert_eq!(&*raw, "a_future_status"),
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn sanitize_error_field_strips_control_characters() {
        assert_eq!(sanitize_error_field("line1\r\nline2\ttab"), "line1line2tab");
    }

    #[test]
    fn sanitize_error_field_truncates_long_input() {
        let long = "a".repeat(500);
        assert_eq!(
            sanitize_error_field(&long).chars().count(),
            MAX_ERROR_FIELD_LEN
        );
    }

    #[test]
    fn parse_retry_after_reads_delta_seconds() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("120"));
        assert_eq!(parse_retry_after(&headers), Some(Duration::from_secs(120)));
    }

    #[test]
    fn parse_retry_after_clamps_to_the_maximum() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("999999999999"));
        assert_eq!(parse_retry_after(&headers), Some(MAX_RETRY_AFTER));
    }

    #[test]
    fn parse_retry_after_ignores_non_numeric_values() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            RETRY_AFTER,
            HeaderValue::from_static("Wed, 21 Oct 2015 07:28:00 GMT"),
        );
        assert_eq!(parse_retry_after(&headers), None);
    }

    #[test]
    fn parse_retry_after_is_none_when_absent() {
        let headers = reqwest::header::HeaderMap::new();
        assert_eq!(parse_retry_after(&headers), None);
    }
}
