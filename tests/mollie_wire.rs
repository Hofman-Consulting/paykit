//! Wiremock-based integration tests for the Mollie provider's wire behaviour.
//!
//! The whole file is gated on the `mollie` feature: without it there is no provider
//! to exercise, and an ungated file breaks the `--no-default-features` CI job.
//!
//! These exercise `MollieProvider` end-to-end over HTTP against a mock server, rather than
//! unit-testing its internals, so they catch the class of bug that only shows up in what
//! actually goes over the wire: the wrong header, the wrong path, the wrong decimal amount,
//! a body that never actually carries the field a serde attribute claims it does, a status
//! this crate silently mis-mapped.
//!
//! This file intentionally does **not** re-cover ground the unit tests in
//! `src/providers/mollie/mod.rs` already cover (error-status mapping, unknown-status
//! decoding, id-mismatch rejection, cancel, refund, idempotency, zero-decimal currencies,
//! `fetch_verified`'s amount/currency check, ...) — those tests already assert on the
//! request path and are cheaper to run. Keeping both would mean two suites that can quietly
//! disagree, and less code is better. What stays here is what a unit test genuinely cannot
//! exercise: real headers and real bytes on an actual socket, path matching, and timeout
//! behaviour driven by a real (delayed) connection.
//!
//! The provider is pointed at the mock server via
//! `MollieProvider::builder(key).insecure_base_url_for_testing(uri)`, the test-only escape
//! hatch around the builder's normal https-only restriction.
//!
//! Response bodies mirror Mollie's real wire shape (`_links.checkout.href`,
//! `amount: {currency, value}`, `metadata`) rather than a minimal shape invented for the
//! test, so a serde attribute typo shows up here instead of in production.

#![cfg(feature = "mollie")]

use std::time::Duration;

use paykit::providers::mollie::MollieProvider;
use paykit::{CreatePayment, Currency, Error, Money, PaymentProvider, PaymentStatus};
use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Builds a `MollieProvider` pointed at `mock_server` via the test-only insecure base URL
/// escape hatch.
fn provider_for(mock_server: &MockServer, api_key: &str) -> MollieProvider {
    MollieProvider::builder(api_key)
        .insecure_base_url_for_testing(mock_server.uri())
        .build()
        .expect("provider should build against a mock server")
}

/// A realistic Mollie payment resource, matching the real API's wire shape.
fn payment_json(id: &str, status: &str, amount_value: &str, currency: &str) -> Value {
    json!({
        "resource": "payment",
        "id": id,
        "mode": "test",
        "description": "Order #1234",
        "status": status,
        "amount": { "currency": currency, "value": amount_value },
        "metadata": { "order_id": "order-1234" },
        "isCancelable": true,
        "createdAt": "2026-08-14T09:00:00+00:00",
        "_links": {
            "self": {
                "href": format!("https://api.mollie.com/v2/payments/{id}"),
                "type": "application/hal+json"
            },
            "checkout": {
                "href": format!("https://www.mollie.com/checkout/select-method/{id}"),
                "type": "text/html"
            },
            "dashboard": {
                "href": format!("https://my.mollie.com/dashboard/org_123/payments/{id}"),
                "type": "text/html"
            }
        }
    })
}

/// A realistic Mollie error response, matching the real API's Problem-ish error shape.
fn error_json(status: u16, title: &str, detail: &str) -> Value {
    json!({
        "status": status,
        "title": title,
        "detail": detail,
        "_links": {
            "documentation": {
                "href": "https://docs.mollie.com/errors",
                "type": "text/html"
            }
        }
    })
}

// --- create_payment ---

#[tokio::test]
async fn create_payment_happy_path() {
    let mock_server = MockServer::start().await;
    let response = payment_json("tr_WDqYK6vllg", "open", "10.00", "EUR");

    Mock::given(method("POST"))
        .and(path("/payments"))
        .respond_with(ResponseTemplate::new(201).set_body_json(&response))
        .expect(1)
        .mount(&mock_server)
        .await;

    let api_key = "test_apikeyABCDEF1234567890";
    let provider = provider_for(&mock_server, api_key);

    let req = CreatePayment::new(
        Money::from_minor(1000, Currency::EUR),
        "Order #1234",
        "https://shop.example/checkout/return",
    )
    .with_webhook_url("https://shop.example/webhooks/mollie")
    .with_reference("order-1234");

    let payment = provider
        .create_payment(req)
        .await
        .expect("create_payment should succeed");

    assert_eq!(payment.id, "tr_WDqYK6vllg");
    assert_eq!(payment.status, PaymentStatus::Open);
    assert_eq!(
        payment.checkout_url.as_deref(),
        Some("https://www.mollie.com/checkout/select-method/tr_WDqYK6vllg")
    );
    // The response's `metadata` uses a plain "order_id" key rather than this crate's
    // internal reserved reference key, so it round-trips as ordinary metadata rather than
    // `payment.reference` — this is what actually exercises the metadata decode path,
    // which nothing in this test previously checked.
    assert_eq!(payment.reference, None);
    assert_eq!(
        payment.metadata.get("order_id").map(String::as_str),
        Some("order-1234"),
        "the response's metadata object must round-trip onto Payment::metadata"
    );

    let requests = mock_server
        .received_requests()
        .await
        .expect("request recording should be enabled");
    assert_eq!(requests.len(), 1);
    let request = &requests[0];

    let auth = request
        .headers
        .get("authorization")
        .expect("Authorization header must be present")
        .to_str()
        .expect("header value should be valid ASCII");
    assert_eq!(auth, format!("Bearer {api_key}"));

    assert!(
        request.headers.get("idempotency-key").is_some(),
        "Idempotency-Key header must be present"
    );

    let body: Value = serde_json::from_slice(&request.body).expect("body should be JSON");
    assert_eq!(body["amount"]["value"], "10.00");
    assert_eq!(body["amount"]["currency"], "EUR");
    // `with_webhook_url` is the crate's entire mechanism for getting Mollie to call back on
    // payment status changes: if `#[serde(rename = "webhookUrl")]` were ever misspelled,
    // Mollie would silently never call the webhook and orders would never confirm. Nothing
    // in this suite previously asserted the field made it into the outbound body at all.
    assert_eq!(
        body["webhookUrl"], "https://shop.example/webhooks/mollie",
        "webhookUrl must be present in the request body with the value the caller supplied"
    );
}

// --- get_payment ---

#[tokio::test]
async fn get_payment_happy_path() {
    let mock_server = MockServer::start().await;
    let response = payment_json("tr_WDqYK6vllg", "paid", "10.00", "EUR");

    Mock::given(method("GET"))
        .and(path("/payments/tr_WDqYK6vllg"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .mount(&mock_server)
        .await;

    let provider = provider_for(&mock_server, "test_apikey");
    let payment = provider
        .get_payment("tr_WDqYK6vllg")
        .await
        .expect("get_payment should succeed");

    assert_eq!(payment.id, "tr_WDqYK6vllg");
    assert_eq!(payment.status, PaymentStatus::Paid);
    assert_eq!(payment.amount, Money::from_minor(1000, Currency::EUR));
}

// --- fetch_verified: the paid-status requirement ---

#[tokio::test]
async fn fetch_verified_rejects_a_matching_amount_that_is_not_yet_paid() {
    // The trap the paid-status requirement exists to close: a real payment, for the right
    // amount, that Mollie has not actually settled yet. Treating this as verified would let
    // a still-open (or pending, authorized, ...) payment confirm an order.
    let mock_server = MockServer::start().await;
    let response = payment_json("tr_verify_notpaid", "open", "10.00", "EUR");

    Mock::given(method("GET"))
        .and(path("/payments/tr_verify_notpaid"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&response))
        .mount(&mock_server)
        .await;

    let provider = provider_for(&mock_server, "test_apikey");
    let expected = Money::from_minor(1000, Currency::EUR);

    let err = provider
        .fetch_verified("tr_verify_notpaid", expected)
        .await
        .expect_err("a matching amount on a non-paid status must still be rejected");

    match err {
        // `..` is required, not stylistic: `Error::NotPaid` is a `#[non_exhaustive]`
        // struct variant, so matching it from outside this crate without `..` is a
        // compile error.
        Error::NotPaid { status, .. } => assert_eq!(status, PaymentStatus::Open),
        other => panic!("expected NotPaid, got {other:?}"),
    }
}

// --- timeout ---

#[tokio::test]
async fn a_slow_response_times_out_and_is_retriable() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/payments/tr_slow"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(payment_json("tr_slow", "open", "10.00", "EUR"))
                .set_delay(Duration::from_millis(200)),
        )
        .mount(&mock_server)
        .await;

    let provider = MollieProvider::builder("test_apikey")
        .insecure_base_url_for_testing(mock_server.uri())
        .timeout(Duration::from_millis(1))
        .build()
        .expect("provider should build against a mock server");

    let err = provider.get_payment("tr_slow").await.unwrap_err();

    assert!(matches!(err, Error::Timeout), "got {err:?}");
    assert!(
        err.is_retriable(),
        "a timeout must be retriable — the request may simply not have arrived"
    );
}

// --- malformed responses ---

#[tokio::test]
async fn non_json_body_is_a_decode_error() {
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/payments/tr_x"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html>not json</html>"))
        .mount(&mock_server)
        .await;

    let provider = provider_for(&mock_server, "test_apikey");
    let err = provider.get_payment("tr_x").await.unwrap_err();

    assert!(matches!(err, Error::Decode { .. }), "got {err:?}");
}

#[tokio::test]
async fn json_missing_required_fields_is_a_decode_error() {
    let mock_server = MockServer::start().await;
    // Valid JSON, but missing `id` and `amount` — a shape no real Mollie response takes.
    let body = json!({ "status": "open" });

    Mock::given(method("GET"))
        .and(path("/payments/tr_x"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&body))
        .mount(&mock_server)
        .await;

    let provider = provider_for(&mock_server, "test_apikey");
    let err = provider.get_payment("tr_x").await.unwrap_err();

    assert!(matches!(err, Error::Decode { .. }), "got {err:?}");
}

// --- secret hygiene ---

#[tokio::test]
async fn api_key_never_leaks_via_provider_debug() {
    let mock_server = MockServer::start().await;
    let api_key = "test_secret_should_never_be_printed_98765";
    let provider = provider_for(&mock_server, api_key);

    assert!(!format!("{provider:?}").contains(api_key));
}

#[tokio::test]
async fn api_key_never_leaks_via_error_display_or_debug() {
    let mock_server = MockServer::start().await;
    let api_key = "test_secret_should_never_be_printed_98765";

    // Craft a 422 body that happens to embed the request's own credential, simulating a
    // provider response (or proxy error page) that echoes request data back. The raw body
    // is captured on `Error::Api` for debugging via `Error::raw_body()`, but must never
    // surface through `Display` or `Debug`.
    let body = json!({
        "status": 422,
        "title": "Unprocessable Entity",
        "detail": "validation failed",
        "_embedded": { "echoed_request": format!("Authorization: Bearer {api_key}") }
    });

    Mock::given(method("POST"))
        .and(path("/payments"))
        .respond_with(ResponseTemplate::new(422).set_body_json(&body))
        .mount(&mock_server)
        .await;

    let provider = provider_for(&mock_server, api_key);
    let req = CreatePayment::new(
        Money::from_minor(1000, Currency::EUR),
        "Order #1234",
        "https://shop.example/checkout/return",
    );
    let err = provider.create_payment(req).await.unwrap_err();

    assert!(!format!("{err}").contains(api_key));
    assert!(!format!("{err:?}").contains(api_key));
    assert!(!format!("{provider:?}").contains(api_key));
}

#[tokio::test]
async fn api_key_never_leaks_via_error_detail_field() {
    // Unlike `_embedded` above — which only ever reaches `raw_body`, a field this crate
    // already excludes from `Display`/`Debug` by construction — Mollie's `detail` is a
    // modeled field on `Error::Api`. A credential landing there (an echoing proxy, a
    // misconfigured Mollie sandbox, ...) is a real path to a leak that the `_embedded` case
    // does not exercise at all.
    let mock_server = MockServer::start().await;
    let api_key = "test_secret_should_never_be_printed_98765";

    let body = error_json(
        422,
        "Unprocessable Entity",
        &format!("Authorization: Bearer {api_key}"),
    );

    Mock::given(method("POST"))
        .and(path("/payments"))
        .respond_with(ResponseTemplate::new(422).set_body_json(&body))
        .mount(&mock_server)
        .await;

    let provider = provider_for(&mock_server, api_key);
    let req = CreatePayment::new(
        Money::from_minor(1000, Currency::EUR),
        "Order #1234",
        "https://shop.example/checkout/return",
    );
    let err = provider.create_payment(req).await.unwrap_err();

    assert!(matches!(err, Error::Api { .. }), "got {err:?}");
    assert!(!format!("{err}").contains(api_key));
    assert!(!format!("{err:?}").contains(api_key));
}
