# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the crate is pre-1.0, breaking changes may land in a minor release.

Note that `reqwest` is a **public dependency** (see the README): a breaking `reqwest`
release forces a breaking release here, and such releases are called out under
`Changed` with a `BREAKING` marker.

## [Unreleased]

### Added

### Changed

### Deprecated

### Removed

### Fixed

### Security

## [0.1.0] - 2026-08-14

Initial release.

### Added

- `PaymentProvider` trait covering payment creation, retrieval, cancellation and refunds.
  The trait is object-safe, so providers can be injected as `Arc<dyn PaymentProvider>` and
  replaced with a test double without changing call sites. `cancel_payment` and `refund`
  have default bodies returning `Error::Unsupported`, so the trait can gain new methods in a
  minor release without breaking existing implementations.
- `PaymentProvider::fetch_verified`, the crate's headline security control: a default-bodied
  trait method (reachable through `Arc<dyn PaymentProvider>`, not just a concrete provider
  type) that fetches a payment and requires **both** that its amount and currency exactly
  match a caller-supplied expected `Money` (`Error::AmountMismatch` otherwise) **and** that
  its status is `PaymentStatus::Paid` (`Error::NotPaid` otherwise) before handing back a
  `VerifiedPayment`.
- `VerifiedPayment`, a wrapper whose only public constructor path is a successful
  `fetch_verified` call — it has no public constructor, `Default`, `From`, or `Deserialize`
  impl, so holding one is itself proof of a verifying call. It does not prove the payment
  belongs to any particular order; callers still look orders up by their own stored payment
  id.
- Core domain types, free of any HTTP dependency: `Money` and `Currency` (integer minor
  units, ISO 4217 exponent aware — no floating point is used for an amount anywhere in the
  crate), `Payment`, `PaymentStatus`, `CreatePayment`, `Refund`, `RefundRequest` and
  `RefundStatus`.
- `Money::parse_decimal` / `Money::to_decimal_string` convert to and from the decimal
  strings providers use on the wire, with every arithmetic step checked so an overflowing
  amount is rejected rather than silently wrapped. `parse_decimal` tolerates redundant
  trailing zeros beyond a currency's precision on input (e.g. `"10.000"` for EUR) while still
  rejecting a fraction that would actually lose precision (e.g. `"10.999"` for EUR).
- `Money` implements `PartialOrd` but deliberately not `Ord`: comparing amounts in different
  currencies is meaningless without an exchange rate, so `partial_cmp` returns `None` on a
  currency mismatch instead of comparing raw minor units.
- `PaymentStatus` and `RefundStatus` are `#[non_exhaustive]` with an `Unknown(Box<str>)`
  catch-all that preserves an unrecognised provider status verbatim rather than failing to
  decode, plus `Display`, `as_str()` and `raw()` for logging and persistence.
- `CreatePayment::new` materializes an idempotency key eagerly, so retrying the same
  `CreatePayment` value (e.g. after a `5xx` or `Error::Timeout`) reuses the same key instead
  of creating a second, duplicate live payment; `CreatePayment::with_idempotency_key`
  overrides it. Setters across `CreatePayment`, `Payment` and `RefundRequest` follow a
  consistent `with_*` naming convention, and getters have no `get_` prefix.
- `RefundRequest::new(amount: Money)` requires the refund amount up front: Mollie declares
  `amount` a required field on its refund endpoint and always rejects a request that omits
  it, so there is no "omit for a full refund" case to model — pass the payment's own amount
  explicitly for a full refund.
- `Error`, a `thiserror` enum distinguishing transport failures, provider-returned API
  errors (with the HTTP status), rate limiting, not-found/unauthorized responses, response
  deserialization failures, and `Error::NotPaid` (an unpaid status from `fetch_verified`) —
  so callers can tell a retryable problem from a permanent one via `Error::is_retriable`.
  `Error` and most of its variants are `#[non_exhaustive]`, constructed via `Error::api`,
  `Error::decode`, `Error::rate_limited`, `Error::not_found`, `Error::unauthorized` and
  `Error::not_paid` rather than struct literals, so new fields can be added in a minor
  release. `Error::NotFound` and `Error::Unauthorized` carry an optional raw response body,
  reachable only via `Error::raw_body`, never via `Display`/`Debug`.
- Mollie provider implementation behind the `mollie` feature, including idempotency keys on
  payment creation, mapping of Mollie's payment and refund states onto `PaymentStatus` /
  `RefundStatus`, and webhook helpers (`is_valid_payment_id`, `parse_webhook_body`) for
  pulling a payment id out of Mollie's unauthenticated, unsigned webhook body before handing
  off to `fetch_verified`.
- Feature flags: `mollie` (default), `rustls-tls` (default), `native-tls`, and `serde`
  (derives `Serialize`/`Deserialize` on the domain types — `Payment`, `Money`,
  `PaymentStatus`, `Refund`, `RefundStatus` — for callers that persist or forward them;
  `serde` itself is always a dependency, so this flag gates only the derives). Building with
  `--no-default-features` yields the traits and types with no HTTP stack, for implementing
  the trait over your own transport.
- A `compile_error!` when the `mollie` feature is enabled without a TLS backend, rather than
  letting every HTTPS request fail at runtime.
- Public re-export of `reqwest` under the `mollie` feature, so callers can build a client
  from the exact version this crate links against and share one connection pool with the
  rest of their application.
- No `uuid` (or other ID-generation) dependency: idempotency keys are derived from
  process-local state (wall-clock time, a monotonic counter and `HashMap`'s own per-process
  keying) mixed with the request content, so the core crate stays buildable with
  `--no-default-features`.
- `#![forbid(unsafe_code)]` and `#![deny(missing_docs)]`.

### Security

- Documented the integrator's responsibilities in `SECURITY.md`: comparing amount and
  currency against your own stored order total (now enforced by `fetch_verified` on the
  crate's behalf, together with the paid-status check), failing closed on mismatch, joining
  on your own stored payment id rather than provider-echoed metadata, a forward-only status
  machine enforced under a row lock, re-fetching from the provider instead of trusting a
  webhook body, webhook response discipline, reconciliation that defers rather than cancels
  on provider errors, and rate limiting the webhook endpoint.
- Crate-level docs state explicitly that verifying a payment is not the same as verifying an
  order, and that an unrecognised `PaymentStatus` must be treated as "defer", never as a
  failure or cancel path.

[Unreleased]: https://github.com/Hofman-Consulting/paykit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Hofman-Consulting/paykit/releases/tag/v0.1.0
