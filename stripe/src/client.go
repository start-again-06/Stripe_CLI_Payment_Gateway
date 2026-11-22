// Package stripe is a small, dependency-free client for the parts of the Stripe
// API this service uses: Checkout Sessions and webhook signature verification.
package stripe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const defaultBaseURL = "https://api.stripe.com/v1"

// Client calls the Stripe REST API with a secret key.
type Client struct {
	secretKey string
	baseURL   string
	http      *http.Client
}

// NewClient returns a Client that talks to the live Stripe API.
func NewClient(secretKey string) *Client {
	return &Client{
		secretKey: secretKey,
		baseURL:   defaultBaseURL,
		http:      &http.Client{Timeout: 30 * time.Second},
	}
}

// LineItem is one priced item on a Checkout Session. Amounts are in the
// currency's smallest unit (cents for USD).
type LineItem struct {
	Name        string
	AmountCents int64
	Currency    string
	Quantity    int64
}

// CheckoutParams describes a one-time payment Checkout Session.
type CheckoutParams struct {
	Items          []LineItem
	SuccessURL     string
	CancelURL      string
	CustomerEmail  string
	Metadata       map[string]string
	IdempotencyKey string
}

// CheckoutSession is the subset of the Stripe Checkout Session object we use.
type CheckoutSession struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

// APIError is returned when Stripe responds with a non-2xx status.
type APIError struct {
	StatusCode int
	Type       string
	Code       string
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("stripe: HTTP %d (%s/%s): %s", e.StatusCode, e.Type, e.Code, e.Message)
}

// Validate checks the parameters before any network call is made.
func (p CheckoutParams) Validate() error {
	if len(p.Items) == 0 {
		return errors.New("at least one line item is required")
	}
	for i, it := range p.Items {
		switch {
		case strings.TrimSpace(it.Name) == "":
			return fmt.Errorf("item %d: name is required", i)
		case it.AmountCents <= 0:
			return fmt.Errorf("item %d: amount must be positive", i)
		case len(it.Currency) != 3:
			return fmt.Errorf("item %d: currency must be a 3-letter ISO code", i)
		case it.Quantity < 1:
			return fmt.Errorf("item %d: quantity must be at least 1", i)
		}
	}
	if p.SuccessURL == "" || p.CancelURL == "" {
		return errors.New("success and cancel URLs are required")
	}
	return nil
}

// CreateCheckoutSession creates a hosted Checkout page for a one-time payment.
func (c *Client) CreateCheckoutSession(ctx context.Context, p CheckoutParams) (*CheckoutSession, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}

	form := url.Values{}
	form.Set("mode", "payment")
	form.Set("success_url", p.SuccessURL)
	form.Set("cancel_url", p.CancelURL)
	if p.CustomerEmail != "" {
		form.Set("customer_email", p.CustomerEmail)
	}
	for i, it := range p.Items {
		prefix := fmt.Sprintf("line_items[%d]", i)
		form.Set(prefix+"[quantity]", strconv.FormatInt(it.Quantity, 10))
		form.Set(prefix+"[price_data][currency]", strings.ToLower(it.Currency))
		form.Set(prefix+"[price_data][unit_amount]", strconv.FormatInt(it.AmountCents, 10))
		form.Set(prefix+"[price_data][product_data][name]", it.Name)
	}
	for k, v := range p.Metadata {
		form.Set("metadata["+k+"]", v)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/checkout/sessions", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.secretKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if p.IdempotencyKey != "" {
		req.Header.Set("Idempotency-Key", p.IdempotencyKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("stripe: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("stripe: reading response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, parseAPIError(resp.StatusCode, body)
	}

	var session CheckoutSession
	if err := json.Unmarshal(body, &session); err != nil {
		return nil, fmt.Errorf("stripe: decoding session: %w", err)
	}
	return &session, nil
}

func parseAPIError(status int, body []byte) error {
	var wrapper struct {
		Error struct {
			Type    string `json:"type"`
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	apiErr := &APIError{StatusCode: status, Message: strings.TrimSpace(string(body))}
	if json.Unmarshal(body, &wrapper) == nil && wrapper.Error.Message != "" {
		apiErr.Type = wrapper.Error.Type
		apiErr.Code = wrapper.Error.Code
		apiErr.Message = wrapper.Error.Message
	}
	return apiErr
}
