# Stripe Payments (Go)

A small Go service for one-time card payments with Stripe:

- `POST /checkout` creates a hosted Stripe Checkout Session and returns its URL.
- `POST /webhook` verifies the Stripe signature on incoming events and handles `checkout.session.completed` and `payment_intent.payment_failed`.
- `GET /success` and `GET /cancel` are the pages customers land on after Checkout.

The Stripe integration uses only the Go standard library. There is no SDK to install, and `go.mod` has no dependencies.

## Project layout

```
.
├── main.go                 HTTP server, routes, webhook dispatch
├── stripe/
│   ├── client.go           Checkout Session creation and API errors
│   ├── webhook.go          Stripe-Signature verification (HMAC-SHA256, timestamp tolerance)
│   ├── events.go           Event envelope and object types
│   └── stripe_test.go      Tests for signing, encoding, validation, and error handling
├── .env.example            Environment variables to set
├── .gitignore
└── README.md
```

## Prerequisites

- Go 1.22 or newer (tested with Go 1.24).
- A Stripe account in test mode.
- The [Stripe CLI](https://docs.stripe.com/stripe-cli), signed in with `stripe login`.

## Configuration

| Variable | Required | Purpose |
|---|---|---|
| `STRIPE_SECRET_KEY` | yes | Test secret key, `sk_test_...` |
| `STRIPE_WEBHOOK_SECRET` | yes | Webhook signing secret, `whsec_...`. Printed by `stripe listen` |
| `PUBLIC_BASE_URL` | no | Base URL used for redirects. Default `http://localhost:4242` |
| `PORT` | no | Listen port. Default `4242` |

Never commit real keys. `.env` is listed in `.gitignore`.

## Run it locally

Open three terminals.

**1. Start the server**

```bash
cp .env.example .env          # then put in your real test keys
set -a; source .env; set +a
go run .
```

**2. Forward Stripe webhooks to the server**

```bash
stripe listen --forward-to localhost:4242/webhook
```

The CLI prints a signing secret that starts with `whsec_`. Put it in `STRIPE_WEBHOOK_SECRET`, then restart the server so it picks up the value.

**3. Create a checkout session and pay**

```bash
curl -s -X POST localhost:4242/checkout \
  -H 'Content-Type: application/json' \
  -d '{"name":"Pro plan","amount_cents":2500,"currency":"usd","quantity":1,"email":"buyer@example.com"}'
```

The response includes a `url`. Open it and pay with a Stripe test card, such as `4242 4242 4242 4242` with any future expiry date and any CVC. The server logs `checkout ... completed`, and the CLI shows the forwarded event.

You can also trigger events without a browser:

```bash
stripe trigger checkout.session.completed
stripe trigger payment_intent.payment_failed
```

## Request reference

### `POST /checkout`

| Field | Type | Notes |
|---|---|---|
| `name` | string | Product name shown on Checkout. Required |
| `amount_cents` | integer | Price in the currency's smallest unit, so 2500 is $25.00. Must be positive |
| `currency` | string | 3-letter ISO code, such as `usd` or `eur` |
| `quantity` | integer | Defaults to 1 |
| `email` | string | Optional. Pre-fills the email field on Checkout |
| `idempotency_key` | string | Optional. Stripe returns the same session for a repeated key |

Responses: `201` with `{"id": "cs_...", "url": "https://checkout.stripe.com/..."}`. `400` for invalid input. `502` when Stripe rejects the request.

### `POST /webhook`

Requires a valid `Stripe-Signature` header. Requests with a bad signature or a timestamp older than five minutes get `400`. Events are deduplicated by ID in memory, so a retried delivery is acknowledged without repeating the work. If a handler fails, the server returns `500` and Stripe retries the event.

## Testing

```bash
go vet ./...
go test ./... -v
```

The tests cover:

- Signature verification: valid, wrong secret, tampered body, stale timestamp, disabled tolerance, missing header, and rotated signatures.
- Checkout encoding: form fields, the `Authorization` header, the idempotency key, and metadata. Uses a local `httptest` server, so no network is needed.
- Stripe error responses are returned as typed `*APIError` values.
- Input validation for line items and URLs.
- Event parsing.

## Going to production

- Set live keys and a live webhook endpoint in the Stripe dashboard. Use its signing secret, not the one from `stripe listen`.
- Replace the in-memory event dedupe with a database table keyed by event ID, so it survives restarts and works across several instances.
- In `dispatch`, fulfil orders only when `payment_status` is `paid`, and make fulfilment idempotent.
- Serve over HTTPS and restrict CORS if the checkout endpoint is called from a browser.
- Add authentication to `POST /checkout` so that anonymous clients cannot create sessions at arbitrary prices. Price on the server from your own catalogue, not from the client's `amount_cents`.
- Consider Stripe's Price and Product objects instead of inline `price_data`, so prices live in the dashboard.

## Limitations

- One-time payments only. Subscriptions and Connect payouts are not implemented.
- No persistent storage. Orders and processed events are only in memory.
- No frontend. Use the returned URL, or build a page that redirects to it.
- Amounts are not checked against a catalogue. This demo trusts the request body, so do not expose `/checkout` publicly without the authentication step above.
