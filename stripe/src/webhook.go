package stripe

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// DefaultWebhookTolerance is how old a signed webhook may be before it is rejected.
// Stripe's own SDKs use five minutes.
const DefaultWebhookTolerance = 5 * time.Minute

var (
	ErrMissingSignature   = errors.New("stripe: Stripe-Signature header is missing a timestamp or v1 signature")
	ErrTimestampTolerance = errors.New("stripe: webhook timestamp is outside the allowed tolerance")
	ErrSignatureMismatch  = errors.New("stripe: no v1 signature matches the payload")
)

// VerifyWebhookSignature checks a Stripe-Signature header against the raw request
// body, as described at https://stripe.com/docs/webhooks/signatures.
//
// The payload must be the exact bytes Stripe sent: parsing and re-encoding the
// JSON first will change the signature. A tolerance of zero disables the
// timestamp check.
func VerifyWebhookSignature(payload []byte, header, secret string, tolerance time.Duration, now time.Time) error {
	timestamp, signatures, err := parseSignatureHeader(header)
	if err != nil {
		return err
	}

	if tolerance > 0 {
		age := now.Sub(time.Unix(timestamp, 0))
		if age > tolerance || age < -tolerance {
			return ErrTimestampTolerance
		}
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(timestamp, 10)))
	mac.Write([]byte("."))
	mac.Write(payload)
	expected := mac.Sum(nil)

	for _, sig := range signatures {
		decoded, err := hex.DecodeString(sig)
		if err != nil {
			continue
		}
		if hmac.Equal(decoded, expected) {
			return nil
		}
	}
	return ErrSignatureMismatch
}

// parseSignatureHeader extracts the timestamp and all v1 signatures.
// Example header: "t=1700000000,v1=abc...,v0=...". Unknown schemes are ignored.
func parseSignatureHeader(header string) (int64, []string, error) {
	var (
		timestamp  int64
		haveTime   bool
		signatures []string
	)
	for _, part := range strings.Split(header, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch key {
		case "t":
			ts, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return 0, nil, fmt.Errorf("stripe: invalid timestamp in signature header: %w", err)
			}
			timestamp, haveTime = ts, true
		case "v1":
			signatures = append(signatures, value)
		}
	}
	if !haveTime || len(signatures) == 0 {
		return 0, nil, ErrMissingSignature
	}
	return timestamp, signatures, nil
}
