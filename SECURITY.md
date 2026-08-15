# Security Policy

## Supported versions

`paykit` is pre-1.0. Only the latest published minor version receives security fixes;
older minors are not backported.

| Version | Supported |
|---|:---:|
| 0.1.x | Yes |
| < 0.1 | No |

Once 1.0 ships, this table will list the current major plus the previous minor.

## Semver policy

`paykit` is pre-1.0, so a breaking change can land in a **minor** release (`0.x`), not just
a major one — there is no major version above `0` to reserve them for. A breaking change
never lands in a patch release.

`Error`, `PaymentStatus`, `RefundStatus`, `Payment`, `Refund`, `ParseCurrencyError` and
`ParseMoneyError` are `#[non_exhaustive]`, several of them with individually
`#[non_exhaustive]` struct variants. That is a contract, not decoration: a new variant, or a
new field on an existing struct/struct variant, can appear in a **patch** release, because
`#[non_exhaustive]` is exactly what makes such an addition non-breaking under semver.
Concretely, this means:

- Always include a wildcard arm (`_ => ...`) when matching on any of these types from
  outside this crate. Code that matches exhaustively today will fail to compile — or, if it
  compiles because it happens to end in a wildcard already, silently fall into that arm — the
  moment a variant is added, and treating an unrecognised match as a hard failure is exactly
  the trap `PaymentStatus::Unknown` and `Error::NotPaid` exist to prevent (see below).
- Construct `#[non_exhaustive]` variants and structs through the provided constructors and
  `with_*` setters (`Error::api`, `Refund::new`, `Payment::new` plus its builders, ...), never
  a struct literal. This is enforced by the compiler outside this crate; the constructors are
  the only way in.
- Do not rely on `Debug` output or exhaustive destructuring for anything you need to keep
  compiling across a `0.x.y -> 0.x'.0` bump.

`reqwest` is a **public dependency**: `MollieProvider::with_client` accepts a caller-supplied
`reqwest::Client`, and this crate re-exports `reqwest` so a caller can construct one from the
exact version it links against. A consumer's `reqwest` `Client` only type-checks against a
`paykit` built against a compatible `reqwest` version. Consequently, **a breaking `reqwest`
release forces a breaking release of `paykit`** — tracked in `CHANGELOG.md` under `Changed`
with a `BREAKING` marker, per the note at the top of that file.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability**, and do not disclose it
on a mailing list, in a pull request, or on social media before a fix is available.

Email **stefan@hofman-consulting.nl** with:

- a description of the issue and why you believe it is a security problem
- the affected version(s) and feature flags
- reproduction steps, or a proof of concept, if you have one
- your assessment of impact, if you have one
- how you would like to be credited (or that you prefer not to be)

You may also use GitHub's [private vulnerability reporting](https://github.com/stefanhofman/paykit/security/advisories/new)
on the repository, which keeps the report confidential until publication.

### What to expect

| Stage | Commitment |
|---|---|
| Acknowledgement of your report | within 3 business days |
| Initial assessment and severity triage | within 7 business days |
| Fix or documented mitigation for a confirmed high-severity issue | within 30 days |
| Public advisory (RustSec + GitHub advisory) | on release of the fix |

If a report turns out to be a design decision rather than a defect, you will get an
explanation of the reasoning rather than silence. Reporters are credited in the advisory
and the changelog unless they ask otherwise.

## Responsibilities of the integrator

`paykit` is a client for a payment provider's API. It reports what the provider says.

`PaymentProvider::fetch_verified` enforces two of the controls below on your behalf: it
refuses to hand back a `VerifiedPayment` unless the provider's amount and currency exactly
match a value you pass in, and unless the provider reports the payment as paid. That is the
full extent of what the crate can enforce — everything else in this checklist depends on
your order data, your database and your transaction boundaries, which the crate has no
visibility into, and it deliberately does **not** guess at them. Even the two checks
`fetch_verified` does perform still depend on you: it only compares against the `Money` you
supply, so getting the right amount out of your own stored order (never out of the payment
or the webhook itself) and calling `fetch_verified` — not `get_payment` — from your webhook
handler remain yours to get right.

Each of these has been the root cause of real-world payment incidents. Treat the list as an
integration checklist.

### 1. Compare amount and currency against your own stored order total

A payment being `Paid` says nothing about *what* was paid. `PaymentProvider::fetch_verified`
does this comparison for you — comparing amounts as integer minor units, never as floats,
with currency as part of the comparison so 100 SEK is never treated as 100 EUR — but only
against the `Money` you pass it. Load your own record of what the customer owed and pass
*that* in; if you pass the payment's own reported amount instead, the check is a no-op.

### 2. Fail closed on mismatch or an unpaid status

`fetch_verified` returns `Err(Error::AmountMismatch { .. })` on a mismatch and
`Err(Error::NotPaid { status })` when the amount matches but the payment is not (yet) paid.
On either error, do not confirm the order and do not refund automatically. Acknowledge the
webhook with a 2xx (so the provider stops retrying), leave the order in an unconfirmed
state, and — for an amount mismatch specifically — raise an alert for manual review. An
amount mismatch is either an integration bug or an attack; both need a human, and neither is
improved by your code guessing. A `NotPaid` result for a status like `Open` or `Pending` is
routine, not an incident: leave the order unconfirmed and let the next webhook or your
reconciliation sweep settle it.

### 3. Look orders up by your own stored payment id

When you create a payment, persist the provider's payment id against your order. That id is
the only join key you should ever use to find the order again.

Never look an order up by a reference, description, metadata field, or redirect parameter
echoed back by the provider. Those values round-trip through a system you do not control,
and some of them originate from data a customer can influence. Treating them as a lookup key
turns "can I influence a metadata field?" into "can I attach my payment to someone else's
order?".

### 4. Enforce a forward-only status machine under a row lock

Payment status must only move forward: `Open → Pending → Authorized → Paid` and the terminal
`Failed` / `Cancelled` / `Expired`. Once an order is `Paid`, no later webhook may move it
back.

Enforce this inside a database transaction that takes a row lock on the order (in
PostgreSQL, `SELECT ... FOR UPDATE`) before reading the current status and writing the new
one. Webhooks arrive concurrently, out of order, and are replayed; without the lock, two
deliveries interleave and the second one clobbers the first. Without the forward-only rule,
a delayed `Open` webhook downgrades a settled payment.

Reject and log any backwards transition rather than applying it.

### 5. Treat an unrecognised status as "defer", never as failure

`PaymentStatus` will gain variants as providers add states. A catch-all arm that releases
stock, cancels the order, or triggers a refund will do exactly that to real paid orders the
first time an unfamiliar status arrives.

The correct handling of an unknown status is to take no action, log it, and let the next
webhook or the reconciliation sweep settle the order. "I don't know" is not "no".

### 6. Trust nothing in a webhook body except the payment id

Webhook endpoints are public. Assume anyone can post anything to yours.

Read the payment id out of the body, then re-fetch the payment from the provider over an
authenticated API call — `fetch_verified(id, expected_amount)` — and use *that* as the
source of truth for status, amount and currency. Never act on a status, amount or metadata
value taken directly from the request body, even when the provider offers a signature —
signature verification tells you the body was not tampered with in transit, not that the
body reflects current state.

### 7. Webhook response discipline

Your status code controls the provider's retry behaviour, so use it deliberately:

- **5xx** — only for transient failures on your side (database unavailable, provider fetch
  timed out). This is what asks the provider to retry, and it is the mechanism that makes
  you eventually consistent.
- **2xx** — for anything you have finished with, *including* input you cannot process:
  unknown payment id, malformed body, unrecognised status, amount mismatch you have already
  alerted on. Returning 5xx for permanently bad input produces a retry storm that you pay
  for in load and the provider eventually gives up on anyway.

Never 5xx on a bug you cannot fix by retrying.

### 8. Run a reconciliation sweep

Webhooks get lost. A periodic job must fetch every payment that has been non-terminal for
longer than expected and reconcile it against the provider — this is the compensating
control that makes lost deliveries survivable, and it is not optional.

Critically: **when the reconciliation job cannot reach the provider, or the provider returns
an error, it must defer — not cancel.** An outage on the provider's side must never be
allowed to cancel paid orders in bulk. Only an explicit terminal status from a successful
API response may move an order to a terminal state.

### 9. Rate limit the webhook endpoint

The endpoint is unauthenticated by design and each request causes an outbound API call to
the provider plus a database transaction. Rate limit it — per source IP and in aggregate —
so it cannot be used to exhaust your connection pool, your provider API quota, or your
worker threads. Cap the accepted request body size while you are at it.

## Scope

In scope for a security report against this crate:

- anything allowing an attacker to influence which order a payment resolves to
- incorrect amount, currency, or status parsing or conversion
- credentials leaking into logs, error messages, or `Debug` output
- TLS or certificate validation being weakened or bypassed
- dependency vulnerabilities reachable through this crate's API

Out of scope:

- vulnerabilities in Mollie's own service (report those to Mollie)
- integrations that skip the responsibilities listed above
- results from running with `native-tls` against a deliberately misconfigured trust store
