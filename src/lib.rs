//! Payment provider abstraction with a Mollie implementation.
//!
//! The crate is built around the [`PaymentProvider`] trait, which is object-safe
//! so providers can be injected as `Arc<dyn PaymentProvider>`.
//!
//! # Security
//!
//! Verifying a payment is **not** the same as verifying an order. This crate can
//! tell you what the provider believes about a payment; it cannot tell you the
//! payment matches what you charged. Always compare the amount and currency
//! against your own stored order total before treating a payment as settled, and
//! look orders up by the provider payment id you stored yourself — never by a
//! reference or metadata value echoed back by the provider.
//!
//! [`PaymentProvider::fetch_verified`] enforces both halves of that check that
//! this crate *can* enforce — the money and the settled status. The order
//! binding remains the caller's responsibility.
#![cfg_attr(
    feature = "mollie",
    doc = "\n\n---\n\nThe README is included below, which makes its usage example a doctest: the \
           first code a crates.io visitor copies is compiled on every CI run rather \
           than left to rot against the real API."
)]
// The README's usage example constructs a `MollieProvider`, so both the
// separator/paragraph above and the include below are gated on the `mollie`
// feature together: without it, there is nothing for either to introduce.
#![cfg_attr(feature = "mollie", doc = include_str!("../README.md"))]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(all(
    feature = "mollie",
    not(any(feature = "rustls-tls", feature = "native-tls"))
))]
compile_error!(
    "the `mollie` feature needs a TLS backend: enable either `rustls-tls` or `native-tls`. \
     Without one the crate compiles, but every HTTPS request fails at runtime."
);

pub mod error;
pub mod money;
pub mod payment;
pub mod provider;
pub mod providers;

pub use error::Error;
pub use money::{Currency, Money, ParseCurrencyError, ParseMoneyError};
pub use payment::{
    CreatePayment, Payment, PaymentStatus, Refund, RefundRequest, RefundStatus, VerifiedPayment,
};
pub use provider::PaymentProvider;

#[cfg(feature = "mollie")]
#[cfg_attr(docsrs, doc(cfg(feature = "mollie")))]
pub use providers::mollie::MollieProvider;

// `reqwest` is part of the public API surface: provider constructors accept a
// caller-supplied `reqwest::Client` so connection pooling can be shared across an
// application. A breaking `reqwest` release is therefore a breaking release here.
#[cfg(feature = "mollie")]
pub use reqwest;
