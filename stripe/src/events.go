package stripe

import "encoding/json"

// Event is the envelope Stripe wraps around every webhook payload.
type Event struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Created int64  `json:"created"`
	Data    struct {
		Object json.RawMessage `json:"object"`
	} `json:"data"`
}

// ParseEvent decodes a verified webhook payload.
func ParseEvent(payload []byte) (*Event, error) {
	var ev Event
	if err := json.Unmarshal(payload, &ev); err != nil {
		return nil, err
	}
	return &ev, nil
}

// CheckoutSessionObject holds the fields we read from checkout.session.* events.
type CheckoutSessionObject struct {
	ID            string            `json:"id"`
	PaymentStatus string            `json:"payment_status"`
	AmountTotal   int64             `json:"amount_total"`
	Currency      string            `json:"currency"`
	CustomerEmail string            `json:"customer_email"`
	Metadata      map[string]string `json:"metadata"`
}

// PaymentIntentObject holds the fields we read from payment_intent.* events.
type PaymentIntentObject struct {
	ID       string `json:"id"`
	Amount   int64  `json:"amount"`
	Currency string `json:"currency"`
	Status   string `json:"status"`
	LastErr  *struct {
		Message string `json:"message"`
		Code    string `json:"code"`
	} `json:"last_payment_error"`
}

// DecodeObject unmarshals the event's data.object into v.
func (e *Event) DecodeObject(v any) error {
	return json.Unmarshal(e.Data.Object, v)
}
