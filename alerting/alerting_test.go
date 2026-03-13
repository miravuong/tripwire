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

func TestBuildDiscordPayload(t *testing.T) {
	payload := BuildDiscordPayload(testEvent())
	if !strings.Contains(payload.Content, "acme/tripwire") {
		t.Fatalf("expected repo in content, got %q", payload.Content)
	}
	if len(payload.Embeds) != 1 {
		t.Fatalf("expected 1 embed, got %d", len(payload.Embeds))
	}
	embed := payload.Embeds[0]
	if embed.Color != 0xFF0000 {
		t.Fatalf("expected red color, got %d", embed.Color)
	}
	foundRule := false
	for _, f := range embed.Fields {
		if f.Name == "Rule" && strings.Contains(f.Value, "aws-access-key-id") {
			foundRule = true
		}
	}
	if !foundRule {
		t.Fatal("expected rule field in embed")
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

func TestBuildSlackPayload(t *testing.T) {
	payload := BuildSlackPayload(testEvent())
	if !strings.Contains(payload.Text, "acme/tripwire") {
		t.Fatalf("expected repo in summary text, got %q", payload.Text)
	}
	if len(payload.Blocks) < 2 {
		t.Fatalf("expected at least 2 blocks, got %d", len(payload.Blocks))
	}
	if payload.Blocks[0].Type != "section" {
		t.Fatalf("expected first block to be section, got %q", payload.Blocks[0].Type)
	}
}

func TestSendDiscord(t *testing.T) {
	var got DiscordPayload
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
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	s := NewSender(srv.Client())
	if err := s.SendDiscord(context.Background(), srv.URL, testEvent()); err != nil {
		t.Fatalf("SendDiscord returned error: %v", err)
	}
	if len(got.Embeds) == 0 {
		t.Fatal("expected embeds in payload")
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
		t.Fatal("expected blocks in Slack payload")
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
