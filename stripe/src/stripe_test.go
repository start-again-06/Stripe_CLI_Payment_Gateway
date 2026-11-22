package stripe

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

const testSecret = "whsec_test_secret"

// sign builds a Stripe-Signature header the same way Stripe does.
func sign(t *testing.T, payload []byte, secret string, ts int64) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(ts, 10)))
	mac.Write([]byte("."))
	mac.Write(payload)
	return "t=" + strconv.FormatInt(ts, 10) + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifyWebhookSignature(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	payload := []byte(`{"id":"evt_1","type":"checkout.session.completed"}`)

	tests := []struct {
		name      string
		payload   []byte
		header    func() string
		secret    string
		tolerance time.Duration
		wantErr   error
	}{
		{
			name:      "valid signature",
			payload:   payload,
			header:    func() string { return sign(t, payload, testSecret, now.Unix()) },
			secret:    testSecret,
			tolerance: DefaultWebhookTolerance,
		},
		{
			name:      "wrong secret",
			payload:   payload,
			header:    func() string { return sign(t, payload, "whsec_other", now.Unix()) },
			secret:    testSecret,
			tolerance: DefaultWebhookTolerance,
			wantErr:   ErrSignatureMismatch,
		},
		{
			name:      "tampered payload",
			payload:   []byte(`{"id":"evt_1","type":"charge.refunded"}`),
			header:    func() string { return sign(t, payload, testSecret, now.Unix()) },
			secret:    testSecret,
			tolerance: DefaultWebhookTolerance,
			wantErr:   ErrSignatureMismatch,
		},
		{
			name:      "stale timestamp",
			payload:   payload,
			header:    func() string { return sign(t, payload, testSecret, now.Add(-10*time.Minute).Unix()) },
			secret:    testSecret,
			tolerance: DefaultWebhookTolerance,
			wantErr:   ErrTimestampTolerance,
		},
		{
			name:      "tolerance disabled accepts old timestamp",
			payload:   payload,
			header:    func() string { return sign(t, payload, testSecret, now.Add(-time.Hour).Unix()) },
			secret:    testSecret,
			tolerance: 0,
		},
		{
			name:      "missing signature",
			payload:   payload,
			header:    func() string { return "t=1700000000" },
			secret:    testSecret,
			tolerance: DefaultWebhookTolerance,
			wantErr:   ErrMissingSignature,
		},
		{
			name:      "empty header",
			payload:   payload,
			header:    func() string { return "" },
			secret:    testSecret,
			tolerance: DefaultWebhookTolerance,
			wantErr:   ErrMissingSignature,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyWebhookSignature(tc.payload, tc.header(), tc.secret, tc.tolerance, now)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestVerifyAcceptsAnyMatchingV1Signature(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	payload := []byte(`{}`)
	good := sign(t, payload, testSecret, now.Unix())
	header := "t=" + strconv.FormatInt(now.Unix(), 10) + ",v1=deadbeef," + strings.TrimPrefix(good, "t="+strconv.FormatInt(now.Unix(), 10)+",")
	if err := VerifyWebhookSignature(payload, header, testSecret, DefaultWebhookTolerance, now); err != nil {
		t.Fatalf("expected rotated signature to verify, got %v", err)
	}
}

func TestCreateCheckoutSessionEncodesRequest(t *testing.T) {
	var gotForm url.Values
	var gotAuth, gotIdem string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/checkout/sessions" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		body, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(body))
		gotAuth = r.Header.Get("Authorization")
		gotIdem = r.Header.Get("Idempotency-Key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cs_test_123","url":"https://checkout.stripe.com/c/pay/cs_test_123"}`))
	}))
	defer srv.Close()

	c := NewClient("sk_test_abc")
	c.baseURL = srv.URL

	session, err := c.CreateCheckoutSession(context.Background(), CheckoutParams{
		Items:          []LineItem{{Name: "Pro plan", AmountCents: 2500, Currency: "USD", Quantity: 2}},
		SuccessURL:     "http://localhost/success",
		CancelURL:      "http://localhost/cancel",
		CustomerEmail:  "buyer@example.com",
		Metadata:       map[string]string{"order": "42"},
		IdempotencyKey: "order-42",
	})
	if err != nil {
		t.Fatalf("CreateCheckoutSession: %v", err)
	}
	if session.ID != "cs_test_123" {
		t.Errorf("session ID = %q", session.ID)
	}
	if gotAuth != "Bearer sk_test_abc" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotIdem != "order-42" {
		t.Errorf("Idempotency-Key = %q", gotIdem)
	}

	want := map[string]string{
		"mode":                                   "payment",
		"success_url":                            "http://localhost/success",
		"cancel_url":                             "http://localhost/cancel",
		"customer_email":                         "buyer@example.com",
		"line_items[0][quantity]":                "2",
		"line_items[0][price_data][currency]":    "usd",
		"line_items[0][price_data][unit_amount]": "2500",
		"line_items[0][price_data][product_data][name]": "Pro plan",
		"metadata[order]": "42",
	}
	for k, v := range want {
		if got := gotForm.Get(k); got != v {
			t.Errorf("form[%s] = %q, want %q", k, got, v)
		}
	}
}

func TestCreateCheckoutSessionSurfacesAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"type":"invalid_request_error","code":"api_key_invalid","message":"Invalid API Key"}}`))
	}))
	defer srv.Close()

	c := NewClient("sk_bad")
	c.baseURL = srv.URL
	_, err := c.CreateCheckoutSession(context.Background(), CheckoutParams{
		Items:      []LineItem{{Name: "x", AmountCents: 100, Currency: "usd", Quantity: 1}},
		SuccessURL: "http://a", CancelURL: "http://b",
	})
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %v", err)
	}
	if apiErr.StatusCode != http.StatusUnauthorized || apiErr.Code != "api_key_invalid" {
		t.Errorf("unexpected error fields: %+v", apiErr)
	}
}

func TestValidateRejectsBadParams(t *testing.T) {
	ok := LineItem{Name: "x", AmountCents: 100, Currency: "usd", Quantity: 1}
	cases := map[string]CheckoutParams{
		"no items":      {SuccessURL: "a", CancelURL: "b"},
		"zero amount":   {Items: []LineItem{{Name: "x", AmountCents: 0, Currency: "usd", Quantity: 1}}, SuccessURL: "a", CancelURL: "b"},
		"bad currency":  {Items: []LineItem{{Name: "x", AmountCents: 1, Currency: "dollars", Quantity: 1}}, SuccessURL: "a", CancelURL: "b"},
		"zero quantity": {Items: []LineItem{{Name: "x", AmountCents: 1, Currency: "usd", Quantity: 0}}, SuccessURL: "a", CancelURL: "b"},
		"missing urls":  {Items: []LineItem{ok}},
	}
	for name, p := range cases {
		if err := p.Validate(); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
	valid := CheckoutParams{Items: []LineItem{ok}, SuccessURL: "a", CancelURL: "b"}
	if err := valid.Validate(); err != nil {
		t.Errorf("valid params rejected: %v", err)
	}
}

func TestParseEventAndDecodeObject(t *testing.T) {
	payload := []byte(`{"id":"evt_9","type":"checkout.session.completed","created":1,
		"data":{"object":{"id":"cs_9","payment_status":"paid","amount_total":2500,"currency":"usd","customer_email":"a@b.c"}}}`)
	ev, err := ParseEvent(payload)
	if err != nil {
		t.Fatal(err)
	}
	if ev.ID != "evt_9" || ev.Type != "checkout.session.completed" {
		t.Fatalf("unexpected event: %+v", ev)
	}
	var cs CheckoutSessionObject
	if err := ev.DecodeObject(&cs); err != nil {
		t.Fatal(err)
	}
	if cs.PaymentStatus != "paid" || cs.AmountTotal != 2500 {
		t.Errorf("unexpected session object: %+v", cs)
	}
}
