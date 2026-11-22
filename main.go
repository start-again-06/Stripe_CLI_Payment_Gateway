// Command stripe-payments is a minimal HTTP service that:
//   - creates Stripe Checkout Sessions for one-time payments (POST /checkout)
//   - receives and verifies Stripe webhooks (POST /webhook)
//
// Configuration (environment variables):
//
//	STRIPE_SECRET_KEY      sk_test_... secret key (required)
//	STRIPE_WEBHOOK_SECRET  whsec_... signing secret (required; printed by `stripe listen`)
//	PUBLIC_BASE_URL        base URL for redirects (default http://localhost:4242)
//	PORT                   listen port (default 4242)
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"stripe-payments/stripe"
)

type server struct {
	client        *stripe.Client
	webhookSecret string
	publicBaseURL string
	logger        *log.Logger

	mu        sync.Mutex
	processed map[string]struct{} // event IDs already handled (in-memory dedupe)
}

type checkoutRequest struct {
	Name           string `json:"name"`
	AmountCents    int64  `json:"amount_cents"`
	Currency       string `json:"currency"`
	Quantity       int64  `json:"quantity"`
	Email          string `json:"email"`
	IdempotencyKey string `json:"idempotency_key"`
}

func main() {
	secret := os.Getenv("STRIPE_SECRET_KEY")
	webhookSecret := os.Getenv("STRIPE_WEBHOOK_SECRET")
	if secret == "" || webhookSecret == "" {
		log.Fatal("set STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET (see README.md)")
	}

	srv := &server{
		client:        stripe.NewClient(secret),
		webhookSecret: webhookSecret,
		publicBaseURL: strings.TrimRight(getenv("PUBLIC_BASE_URL", "http://localhost:4242"), "/"),
		logger:        log.New(os.Stdout, "", log.LstdFlags),
		processed:     make(map[string]struct{}),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", srv.handleHealth)
	mux.HandleFunc("POST /checkout", srv.handleCheckout)
	mux.HandleFunc("POST /webhook", srv.handleWebhook)
	mux.HandleFunc("GET /success", srv.handleSuccess)
	mux.HandleFunc("GET /cancel", srv.handleCancel)

	httpSrv := &http.Server{
		Addr:              ":" + getenv("PORT", "4242"),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		srv.logger.Printf("listening on %s", httpSrv.Addr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		srv.logger.Printf("shutdown: %v", err)
	}
}

func (s *server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleCheckout creates a Checkout Session and returns the hosted payment URL.
//
//	curl -X POST localhost:4242/checkout -H 'Content-Type: application/json' \
//	  -d '{"name":"Pro plan","amount_cents":2500,"currency":"usd","quantity":1}'
func (s *server) handleCheckout(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var req checkoutRequest
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	if req.Quantity == 0 {
		req.Quantity = 1
	}

	session, err := s.client.CreateCheckoutSession(r.Context(), stripe.CheckoutParams{
		Items: []stripe.LineItem{{
			Name:        req.Name,
			AmountCents: req.AmountCents,
			Currency:    req.Currency,
			Quantity:    req.Quantity,
		}},
		SuccessURL:     s.publicBaseURL + "/success",
		CancelURL:      s.publicBaseURL + "/cancel",
		CustomerEmail:  req.Email,
		IdempotencyKey: req.IdempotencyKey,
		Metadata:       map[string]string{"source": "stripe-payments-demo"},
	})
	if err != nil {
		var apiErr *stripe.APIError
		if errors.As(err, &apiErr) {
			s.logger.Printf("checkout failed: %v", err)
			writeError(w, http.StatusBadGateway, apiErr.Message)
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	s.logger.Printf("created checkout session %s", session.ID)
	writeJSON(w, http.StatusCreated, session)
}

// handleWebhook verifies the signature, then dispatches known event types.
// It must respond quickly with 2xx; Stripe retries anything else.
func (s *server) handleWebhook(w http.ResponseWriter, r *http.Request) {
	payload, err := readAllLimited(w, r, 65536)
	if err != nil {
		writeError(w, http.StatusBadRequest, "could not read body")
		return
	}

	if err := stripe.VerifyWebhookSignature(payload, r.Header.Get("Stripe-Signature"),
		s.webhookSecret, stripe.DefaultWebhookTolerance, time.Now()); err != nil {
		s.logger.Printf("webhook rejected: %v", err)
		writeError(w, http.StatusBadRequest, "invalid signature")
		return
	}

	ev, err := stripe.ParseEvent(payload)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid event payload")
		return
	}

	if !s.markProcessed(ev.ID) {
		s.logger.Printf("duplicate event %s (%s) ignored", ev.ID, ev.Type)
		writeJSON(w, http.StatusOK, map[string]string{"status": "duplicate"})
		return
	}

	if err := s.dispatch(ev); err != nil {
		// Returning 500 asks Stripe to retry the event later.
		s.logger.Printf("handling %s (%s) failed: %v", ev.ID, ev.Type, err)
		s.unmarkProcessed(ev.ID)
		writeError(w, http.StatusInternalServerError, "handler failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "received"})
}

func (s *server) dispatch(ev *stripe.Event) error {
	switch ev.Type {
	case "checkout.session.completed":
		var cs stripe.CheckoutSessionObject
		if err := ev.DecodeObject(&cs); err != nil {
			return err
		}
		// Fulfil the order here. Only do so when payment_status is "paid".
		s.logger.Printf("checkout %s completed: status=%s amount=%d %s email=%s",
			cs.ID, cs.PaymentStatus, cs.AmountTotal, strings.ToUpper(cs.Currency), cs.CustomerEmail)

	case "payment_intent.payment_failed":
		var pi stripe.PaymentIntentObject
		if err := ev.DecodeObject(&pi); err != nil {
			return err
		}
		reason := "unknown"
		if pi.LastErr != nil {
			reason = pi.LastErr.Message
		}
		s.logger.Printf("payment %s failed: %s", pi.ID, reason)

	default:
		s.logger.Printf("ignoring event %s (%s)", ev.ID, ev.Type)
	}
	return nil
}

func (s *server) handleSuccess(w http.ResponseWriter, _ *http.Request) {
	writeHTML(w, "Payment received", "Thanks. Your payment was submitted. Confirmation arrives by webhook.")
}

func (s *server) handleCancel(w http.ResponseWriter, _ *http.Request) {
	writeHTML(w, "Payment cancelled", "No charge was made.")
}

// markProcessed records an event ID and reports whether it was new.
func (s *server) markProcessed(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, seen := s.processed[id]; seen {
		return false
	}
	s.processed[id] = struct{}{}
	return true
}

func (s *server) unmarkProcessed(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.processed, id)
}

func readAllLimited(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	return io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeHTML(w http.ResponseWriter, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte("<!doctype html><title>" + title + "</title><h1>" + title + "</h1><p>" + body + "</p>"))
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
