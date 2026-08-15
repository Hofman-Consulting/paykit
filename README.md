# paykit

[![crates.io](https://img.shields.io/crates/v/paykit.svg)](https://crates.io/crates/paykit)
[![docs.rs](https://img.shields.io/docsrs/paykit)](https://docs.rs/paykit)
[![CI](https://github.com/Hofman-Consulting/paykit/actions/workflows/ci.yml/badge.svg)](https://github.com/Hofman-Consulting/paykit/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/MSRV-1.88-blue.svg)](#minimum-supported-rust-version)
[![license](https://img.shields.io/crates/l/paykit.svg)](#license)

A payment-provider abstraction for Rust, with a [Mollie](https://mollie.com) implementation.

`paykit` is built around one object-safe trait, `PaymentProvider`, so an application can
hold an `Arc<dyn PaymentProvider>` and swap providers — or substitute a fake in tests —
without the call sites changing. The core types (`Money`, `Currency`, `Payment`,
`PaymentStatus`) carry no HTTP dependency; the transport arrives with a provider feature.

- Object-safe trait, injectable as `Arc<dyn PaymentProvider>`
- Integer-cent `Money` — no floats anywhere near an amount
- Transport-agnostic core: `--no-default-features` builds without `reqwest`
- `#![forbid(unsafe_code)]`, `#![deny(missing_docs)]`

## Install

```toml
[dependencies]
paykit = "0.1"
```

Default features are `mollie` and `rustls-tls`. For the core traits and types only:

```toml
[dependencies]
paykit = { version = "0.1", default-features = false }
```

## Usage

```rust,no_run
use std::sync::Arc;
use std::time::Duration;

use paykit::{Currency, CreatePayment, Error, Money, PaymentProvider, PaymentStatus};
use paykit::providers::mollie::MollieProvider;

# async fn run() -> Result<(), paykit::Error> {
// Build the client explicitly rather than using `reqwest::Client::new()`: the default
// has no total-request timeout, no connect timeout, and follows up to 10 redirects.
// None of that is what you want for a client that carries this provider's API key on
// every request — an unbounded timeout means a wedged connection hangs your request
// indefinitely, and following redirects could hand the `Authorization` header to
// whatever host a redirect response names. Share one `Client` across the application
// so connection pooling and TLS session reuse are shared too.
let http = paykit::reqwest::Client::builder()
    .connect_timeout(Duration::from_secs(5))
    .timeout(Duration::from_secs(10))
    .redirect(paykit::reqwest::redirect::Policy::none())
    .build()
    .expect("client configuration is valid");
let provider: Arc<dyn PaymentProvider> =
    Arc::new(MollieProvider::with_client("test_xxxxxxxx", http)?);

// Amounts are integer minor units, never floats. The decimal string sent to the
// provider follows the currency's own ISO 4217 exponent — "19.99" for EUR, but
// "1999" for a zero-decimal currency like JPY.
// Your own stored order total — never the payment's own reported amount, which is
// exactly what `fetch_verified` below is there to check against.
let order_total = Money::from_minor(1999, Currency::EUR);

let request = CreatePayment::new(
    order_total,
    "Order #1234",
    "https://shop.example/checkout/return",
)
.with_webhook_url("https://shop.example/webhooks/mollie")
.with_reference("order-1234");

let payment = provider.create_payment(request).await?;

// Send the customer here to pay.
println!("{:?}", payment.checkout_url);

// Later, from your webhook handler: trust only the payment id from the body, then
// re-fetch the payment from the provider via `fetch_verified` — the crate's headline
// security control. It fails unless the fetched payment's amount and currency match
// `order_total` *and* its status is paid, so a `VerifiedPayment` is the only value
// safe to treat as a settled order.
match provider.fetch_verified(&payment.id, order_total).await {
    Ok(verified) => { /* mark the order paid, looked up by `verified.payment().id` */ }
    // `..` is required: these are `#[non_exhaustive]` struct variants, so matching their
    // fields from outside this crate without it is a compile error.
    Err(Error::AmountMismatch { expected, actual, .. }) => {
        // Under/overpayment or wrong currency: fail closed, raise for manual review.
        let _ = (expected, actual);
    }
    Err(Error::NotPaid { status, .. }) => match status {
        PaymentStatus::Failed | PaymentStatus::Cancelled | PaymentStatus::Expired => {
            /* release stock */
        }
        // Anything else, including a status this crate does not recognise: defer.
        _ => {}
    },
    Err(err) => {
        // `Display` deliberately does not render a provider's `title`/`detail` — a
        // compromised or misconfigured provider echoing request content back into
        // either is a realistic credential-leak path (see `Error`'s docs), so nothing
        // pulls them into a log line by default. Reach for them explicitly, here via
        // `Error::title`, only once you know the context you are logging into is safe
        // for provider-supplied text.
        eprintln!("payment verification failed: {err} (title: {:?})", err.title());
        return Err(err);
    }
}
# Ok(())
# }
```

## Feature flags

| Feature | Default | Description |
|---|:---:|---|
| `mollie` | yes | The Mollie provider implementation. Pulls in `reqwest` and `serde_json`. |
| `rustls-tls` | yes | TLS via `rustls`. No system OpenSSL needed; the usual choice. |
| `native-tls` | no | TLS via the platform's native stack (OpenSSL / Schannel / Secure Transport). |
| `serde` | no | `Serialize`/`Deserialize` on `Payment`, `Money`, `PaymentStatus`, `Refund`, `RefundStatus`, for persisting or forwarding them. |

A provider feature needs a TLS backend. Enabling `mollie` with neither `rustls-tls` nor
`native-tls` is a compile error rather than a runtime surprise — without one, the crate
still builds but every HTTPS request fails once you are in production.

**Cargo features are additive across the whole dependency graph, and TLS backend is no
exception.** If your application depends on `paykit` with only `rustls-tls`, but some other
crate in your dependency tree enables `paykit/native-tls` (directly or transitively), your
build silently gets both backends compiled in and, depending on the underlying HTTP client,
may end up using native-tls instead of the one you configured. Cargo has no notion of "my
crate's choice wins" — the union of every enabled feature in the graph is what gets built.
If this matters to you, audit `cargo tree -e features -i paykit` rather than assuming your
own `Cargo.toml` is the last word.

Turning off default features gives you `PaymentProvider`, `Money`, `Payment` and friends
with no HTTP stack at all, which is what you want when implementing the trait against your
own transport or a test double.

## `reqwest` is a public dependency

This is deliberate and it has a versioning consequence, so it is stated up front rather
than buried in the API docs.

Provider constructors accept a caller-supplied `reqwest::Client` (`MollieProvider::with_client`)
so that connection pooling, timeouts, proxy configuration and TLS settings are shared with
the rest of your application instead of `paykit` quietly opening a second pool. `reqwest`
types therefore appear in the public API, and the crate re-exports `paykit::reqwest` so you
can construct a client from the exact version this crate links against.

**A breaking `reqwest` release is a breaking release of `paykit`.** When `reqwest` goes to
0.13, `paykit` will need a major (pre-1.0: minor) version bump, because a consumer passing a
`reqwest` 0.12 `Client` into a `paykit` built against 0.13 gets a type error, not a
deprecation warning. Pin accordingly, and expect this crate's version to track `reqwest`'s
breaking changes as well as its own.

If you want to avoid that coupling entirely, depend on `paykit` with
`default-features = false` and implement `PaymentProvider` over your own HTTP client.

## Security

Read this section before shipping. The failure modes below are the ones that lose money or
cancel real orders, and none of them are things this crate can prevent for you.

**Verifying a payment is not the same as verifying an order.** `paykit` reports what the
provider believes about a payment. It cannot know what you intended to charge. Before you
treat a payment as settled, compare the amount **and** the currency against your own stored
order total. A `Paid` status on a 1.00 EUR payment against a 100.00 EUR order is still
`Paid`. If they do not match, fail closed: acknowledge the webhook, do not confirm the
order, and raise it for manual review.

**Look orders up by the payment id you stored yourself.** Never by a reference, description
or metadata value echoed back by the provider. Those fields round-trip through a system you
do not control and, in some flows, through input a customer can influence. The payment id
you persisted when you created the payment is the only safe join key.

**Treat an unrecognised payment status as "defer, take no action."** Not as a failure, and
not as a cancel path. Providers add statuses; a `match` arm with a catch-all that releases
stock or refunds will happily cancel real, paid orders the day Mollie ships a new state.
The correct catch-all does nothing and leaves the order for the next webhook or for your
reconciliation sweep to resolve.

Further integrator responsibilities — forward-only status transitions under a row lock,
webhook response discipline, reconciliation, rate limiting — are listed in
[SECURITY.md](SECURITY.md).

To report a vulnerability in `paykit` itself, email <stefan@hofman-consulting.nl>. Please do
not open a public issue.

## Minimum supported Rust version

Rust **1.88**. The MSRV is verified in CI against the committed `Cargo.lock`.

Raising the MSRV is treated as a semver-visible change and will come with at least a minor
version bump while this crate is pre-1.0.

## Contributing

Issues and pull requests are welcome. Before opening a PR, please run:

```sh
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo test --no-default-features
```

The last one matters: the core is meant to be transport-agnostic, and it is easy to leak a
`reqwest` reference into it without noticing.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in this crate by you, as defined in the Apache-2.0 license, shall be dual licensed
as above, without any additional terms or conditions.
