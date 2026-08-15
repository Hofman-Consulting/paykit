//! Internal Mollie API wire types.
//!
//! These mirror the JSON shapes Mollie's REST API sends and receives. They
//! are deliberately private to the crate (`pub(crate)`, never re-exported):
//! nothing here is part of the public API, so this module is free to track
//! Mollie's wire format exactly without constraining [`crate::payment`]'s
//! provider-agnostic types.
//!
//! Payment/refund status strings are deserialized as plain [`String`]
//! rather than into a dedicated wire enum: mapping a raw string straight to
//! [`crate::payment::PaymentStatus`] / [`crate::payment::RefundStatus`] (see
//! `payment_status` and `refund_status` in [`super`]) needs no
//! intermediate type, and a hand-written `Deserialize` impl on that
//! intermediate type would just be the same match arms one layer removed.

use serde::{Deserialize, Serialize};

use crate::money::Money;

/// The `amount` object Mollie uses on both requests and responses:
/// `{ "currency": "EUR", "value": "10.00" }`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MollieAmount {
    pub currency: String,
    pub value: String,
}

impl From<Money> for MollieAmount {
    fn from(amount: Money) -> Self {
        Self {
            currency: amount.currency().to_string(),
            value: amount.to_decimal_string(),
        }
    }
}

/// Body sent to `POST /v2/payments`.
#[derive(Debug, Serialize)]
pub(crate) struct CreatePaymentBody {
    pub amount: MollieAmount,
    pub description: String,
    #[serde(rename = "redirectUrl")]
    pub redirect_url: String,
    #[serde(rename = "webhookUrl", skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Response body from `POST /v2/payments`, `GET /v2/payments/{id}`, and the
/// body Mollie returns from a successful `DELETE /v2/payments/{id}`.
#[derive(Debug, Deserialize)]
pub(crate) struct MolliePayment {
    pub id: String,
    /// Raw status string, e.g. `"paid"`. Mapped to
    /// [`crate::payment::PaymentStatus`] by `super::payment_status`, which
    /// preserves anything unrecognized rather than failing to decode.
    pub status: String,
    pub amount: MollieAmount,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
    #[serde(rename = "_links", default)]
    pub links: Option<MollieLinks>,
}

/// `_links` object on a payment response.
#[derive(Debug, Deserialize)]
pub(crate) struct MollieLinks {
    #[serde(default)]
    pub checkout: Option<MollieLink>,
}

/// A single HAL link, e.g. `_links.checkout`.
#[derive(Debug, Deserialize)]
pub(crate) struct MollieLink {
    pub href: String,
}

/// Body sent to `POST /v2/payments/{id}/refunds`.
///
/// `amount` is required: Mollie's API documents `amount` as a required
/// field on this endpoint and returns a 422 ("The 'amount' field is
/// missing") without it, so unlike the payment/refund status fields above
/// there is no "omit for a sensible default" case to model here.
#[derive(Debug, Serialize)]
pub(crate) struct CreateRefundBody {
    pub amount: MollieAmount,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Response body from `POST /v2/payments/{id}/refunds` and
/// `GET /v2/payments/{id}/refunds/{refundId}`.
#[derive(Debug, Deserialize)]
pub(crate) struct MollieRefund {
    pub id: String,
    /// The payment this refund belongs to. Optional on the wire even though
    /// Mollie's documented response always includes it: `super::refund`
    /// already knows which payment it asked to refund, so a response that
    /// omits this field can fall back to that rather than fail to decode
    /// over a field the caller didn't strictly need from the response.
    #[serde(rename = "paymentId", default)]
    pub payment_id: Option<String>,
    pub amount: MollieAmount,
    /// Raw status string, e.g. `"pending"`. See [`MolliePayment::status`].
    pub status: String,
}

/// Mollie's typed error body, returned on non-2xx responses, e.g.
/// `{ "status": 422, "title": "Unprocessable Entity", "detail": "...",
/// "field": "amount" }`. The HTTP status code from the transport layer is
/// authoritative for error mapping, not `status` here, so that field is
/// deliberately not modeled.
#[derive(Debug, Deserialize)]
pub(crate) struct MollieErrorBody {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub field: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_body_tolerates_missing_fields() {
        let body: MollieErrorBody = serde_json::from_str("{}").unwrap();
        assert_eq!(body.title, None);
        assert_eq!(body.detail, None);
        assert_eq!(body.field, None);
    }

    #[test]
    fn error_body_reads_title_detail_and_field() {
        let body: MollieErrorBody = serde_json::from_str(
            r#"{"status":422,"title":"Unprocessable Entity","detail":"amount is required","field":"amount"}"#,
        )
        .unwrap();
        assert_eq!(body.title.as_deref(), Some("Unprocessable Entity"));
        assert_eq!(body.detail.as_deref(), Some("amount is required"));
        assert_eq!(body.field.as_deref(), Some("amount"));
    }

    #[test]
    fn create_payment_body_serializes_mollie_field_names() {
        let body = CreatePaymentBody {
            amount: MollieAmount {
                currency: "EUR".to_string(),
                value: "10.00".to_string(),
            },
            description: "order #1".to_string(),
            redirect_url: "https://shop.example/return".to_string(),
            webhook_url: None,
            metadata: None,
        };
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["redirectUrl"], "https://shop.example/return");
        assert!(json.get("webhookUrl").is_none());
        assert!(json.get("metadata").is_none());
    }

    #[test]
    fn create_refund_body_always_includes_amount_but_omits_absent_description() {
        let body = CreateRefundBody {
            amount: MollieAmount {
                currency: "EUR".to_string(),
                value: "5.00".to_string(),
            },
            description: None,
        };
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["amount"]["currency"], "EUR");
        assert_eq!(json["amount"]["value"], "5.00");
        assert!(json.get("description").is_none());
    }

    #[test]
    fn mollie_refund_decodes_without_payment_id() {
        let refund: MollieRefund = serde_json::from_str(
            r#"{"id":"re_1","amount":{"currency":"EUR","value":"5.00"},"status":"pending"}"#,
        )
        .unwrap();
        assert_eq!(refund.payment_id, None);
    }

    #[test]
    fn money_converts_to_mollie_amount() {
        let amount = MollieAmount::from(Money::from_minor(1234, crate::money::Currency::EUR));
        assert_eq!(amount.currency, "EUR");
        assert_eq!(amount.value, "12.34");
    }
}
