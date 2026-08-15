//! Concrete [`PaymentProvider`](crate::PaymentProvider) implementations.
//!
//! Each provider sits behind its own cargo feature so an application only
//! compiles the ones it uses, and the core stays transport-agnostic.

#[cfg(feature = "mollie")]
#[cfg_attr(docsrs, doc(cfg(feature = "mollie")))]
pub mod mollie;
