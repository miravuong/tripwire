package alerting

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testEvent() Event {
	return Event{
		Repository: "acme/tripwire",
		Branch:     "main",
		CommitSHA:  "abc1234def5678",
		Rule:       "aws-access-key-id",
		FilePath:   "config/settings.py",
		Author:     "dev@example.com",
		DetectedAt: time.Date(2026, 2, 26, 12, 0, 0, 0, time.UTC),
	}
}

func TestBuildSlackPayload(t *testing.T) {
	payload := BuildSlackPayload(testEvent())
	if !strings.Contains(payload.Text, "acme/tripwire") {
		t.Fatalf("expected repo in summary text, got %q", payload.Text)
	}
	if len(payload.Blocks) != 2 {
		t.Fatalf("expected 2 blocks, got %d", len(payload.Blocks))
	}
	if !strings.Contains(payload.Blocks[1].Text.Text, "aws-access-key-id") {
		t.Fatalf("expected rule in detail block, got %q", payload.Blocks[1].Text.Text)
	}
}

func TestBuildWebhookPayload(t *testing.T) {
	payload := BuildWebhookPayload(testEvent())
	if payload.Event != "secret.detected" {
		t.Fatalf("expected secret.detected event, got %q", payload.Event)
	}
	if payload.Repository != "acme/tripwire" {
		t.Fatalf("unexpected repo: %q", payload.Repository)
	}
}

func TestSendSlack(t *testing.T) {
	var got SlackPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Fatalf("expected content type application/json, got %q", ct)
		}
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := NewSender(srv.Client())
	if err := s.SendSlack(context.Background(), srv.URL, testEvent()); err != nil {
		t.Fatalf("SendSlack returned error: %v", err)
	}
	if len(got.Blocks) == 0 {
		t.Fatal("expected slack blocks in payload")
	}
}

func TestSendWebhookNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	s := NewSender(srv.Client())
	err := s.SendWebhook(context.Background(), srv.URL, testEvent())
	if err == nil {
		t.Fatal("expected error for non-2xx response")
	}
	if !strings.Contains(err.Error(), "status 400") {
		t.Fatalf("expected status error, got %v", err)
	}
}

func TestEventValidate(t *testing.T) {
	e := testEvent()
	e.Repository = ""
	if err := e.Validate(); err == nil {
		t.Fatal("expected validation error for empty repository")
	}
}
