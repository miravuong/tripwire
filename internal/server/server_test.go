package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"main/alerting"
	"main/rotation"
)

const testWebhookToken = "test-webhook-token"

type fakeRotationService struct {
	results []rotation.RotationResult
	err     error
	events  []rotation.DetectionEvent
}

func (s *fakeRotationService) RotateAll(_ context.Context, event rotation.DetectionEvent) ([]rotation.RotationResult, error) {
	s.events = append(s.events, event)
	if s.err != nil {
		return nil, s.err
	}
	return s.results, nil
}

type fakeAlertSender struct {
	discordEvents []alerting.Event
	slackEvents   []alerting.Event
	webhookEvents []alerting.Event
	err           error
}

func (s *fakeAlertSender) SendDiscord(_ context.Context, _ string, event alerting.Event) error {
	s.discordEvents = append(s.discordEvents, event)
	return s.err
}

func (s *fakeAlertSender) SendSlack(_ context.Context, _ string, event alerting.Event) error {
	s.slackEvents = append(s.slackEvents, event)
	return s.err
}

func (s *fakeAlertSender) SendWebhook(_ context.Context, _ string, event alerting.Event) error {
	s.webhookEvents = append(s.webhookEvents, event)
	return s.err
}

func TestNewHandlerRequiresWebhookToken(t *testing.T) {
	_, err := NewHandler(Dependencies{
		Config:   Config{},
		Sender:   &fakeAlertSender{},
		Rotation: &fakeRotationService{},
	})
	if err == nil {
		t.Fatal("expected missing token error")
	}
	if !strings.Contains(err.Error(), "token") {
		t.Fatalf("expected token error, got %v", err)
	}
}

func TestLoadConfigFromEnvRequiresWebhookToken(t *testing.T) {
	t.Setenv("LISTEN_ADDR", "")
	t.Setenv("TRIPWIRE_WEBHOOK_TOKEN", "")

	_, err := LoadConfigFromEnv()
	if err == nil {
		t.Fatal("expected missing webhook token error")
	}
}

func TestLoadConfigFromEnvDefaultsListenAddr(t *testing.T) {
	t.Setenv("LISTEN_ADDR", "")
	t.Setenv("TRIPWIRE_WEBHOOK_TOKEN", testWebhookToken)

	config, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("LoadConfigFromEnv returned error: %v", err)
	}
	if config.ListenAddr != DefaultListenAddr {
		t.Fatalf("expected default listen addr %q, got %q", DefaultListenAddr, config.ListenAddr)
	}
}

func TestDetectionWebhookRejectsMissingBearerToken(t *testing.T) {
	rotationSvc := &fakeRotationService{}
	handler := mustHandler(t, Config{DetectionWebhookToken: testWebhookToken}, &fakeAlertSender{}, rotationSvc)

	req := httptest.NewRequest(http.MethodPost, "/webhook/detection", strings.NewReader(validDetectionJSON()))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
	if len(rotationSvc.events) != 0 {
		t.Fatalf("expected no rotation calls, got %d", len(rotationSvc.events))
	}
}

func TestDetectionWebhookRejectsInvalidBearerToken(t *testing.T) {
	rotationSvc := &fakeRotationService{}
	handler := mustHandler(t, Config{DetectionWebhookToken: testWebhookToken}, &fakeAlertSender{}, rotationSvc)

	req := httptest.NewRequest(http.MethodPost, "/webhook/detection", strings.NewReader(validDetectionJSON()))
	req.Header.Set("Authorization", "Bearer wrong-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, rec.Code)
	}
	if len(rotationSvc.events) != 0 {
		t.Fatalf("expected no rotation calls, got %d", len(rotationSvc.events))
	}
}

func TestDetectionWebhookAcceptsAuthenticatedJSON(t *testing.T) {
	rotationSvc := &fakeRotationService{
		results: []rotation.RotationResult{
			{Provider: "noop", Status: "simulated", RotatedAt: fixedTime()},
		},
	}
	alertSender := &fakeAlertSender{}
	handler := mustHandler(t, Config{
		DetectionWebhookToken:  testWebhookToken,
		DiscordWebhookURL:      "https://example.com/discord",
		SlackWebhookURL:        "https://example.com/slack",
		GenericAlertWebhookURL: "https://example.com/webhook",
	}, alertSender, rotationSvc)

	req := authenticatedRequest(http.MethodPost, "/webhook/detection", validDetectionJSON())
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected status %d, got %d: %s", http.StatusAccepted, rec.Code, rec.Body.String())
	}
	if len(rotationSvc.events) != 1 {
		t.Fatalf("expected 1 rotation call, got %d", len(rotationSvc.events))
	}
	event := rotationSvc.events[0]
	if event.Repository != "acme/tripwire" {
		t.Fatalf("expected repository from JSON payload, got %q", event.Repository)
	}
	if len(alertSender.discordEvents) != 1 || len(alertSender.slackEvents) != 1 || len(alertSender.webhookEvents) != 1 {
		t.Fatalf("expected all alert channels to be called, got discord=%d slack=%d webhook=%d",
			len(alertSender.discordEvents),
			len(alertSender.slackEvents),
			len(alertSender.webhookEvents),
		)
	}

	var response struct {
		Status         string `json:"status"`
		RotationsCount int    `json:"rotations_count"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Status != "accepted" || response.RotationsCount != 1 {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestDetectionWebhookDecodesHeaderEvent(t *testing.T) {
	rotationSvc := &fakeRotationService{
		results: []rotation.RotationResult{
			{Provider: "noop", Status: "simulated", RotatedAt: fixedTime()},
		},
	}
	handler := mustHandler(t, Config{DetectionWebhookToken: testWebhookToken}, &fakeAlertSender{}, rotationSvc)

	req := authenticatedRequest(http.MethodPost, "/webhook/detection", "")
	req.Header.Set("X-Repository", "acme/tripwire")
	req.Header.Set("X-Branch", "main")
	req.Header.Set("X-Commit-SHA", "abc1234def5678")
	req.Header.Set("X-Rule", "aws-access-key-id")
	req.Header.Set("X-File-Path", "config/settings.py")
	req.Header.Set("X-Author", "dev@example.com")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected status %d, got %d: %s", http.StatusAccepted, rec.Code, rec.Body.String())
	}
	if len(rotationSvc.events) != 1 {
		t.Fatalf("expected 1 rotation call, got %d", len(rotationSvc.events))
	}
	event := rotationSvc.events[0]
	if event.Source != "http-header" {
		t.Fatalf("expected http-header source, got %q", event.Source)
	}
	if !event.DetectedAt.Equal(fixedTime()) {
		t.Fatalf("expected fixed detected_at, got %s", event.DetectedAt)
	}
}

func TestDetectionWebhookRejectsInvalidJSON(t *testing.T) {
	rotationSvc := &fakeRotationService{}
	handler := mustHandler(t, Config{DetectionWebhookToken: testWebhookToken}, &fakeAlertSender{}, rotationSvc)

	req := authenticatedRequest(http.MethodPost, "/webhook/detection", "{")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, rec.Code)
	}
	if len(rotationSvc.events) != 0 {
		t.Fatalf("expected no rotation calls, got %d", len(rotationSvc.events))
	}
}

func TestDetectionWebhookReturnsRotationFailure(t *testing.T) {
	rotationSvc := &fakeRotationService{err: errors.New("boom")}
	handler := mustHandler(t, Config{DetectionWebhookToken: testWebhookToken}, &fakeAlertSender{}, rotationSvc)

	req := authenticatedRequest(http.MethodPost, "/webhook/detection", validDetectionJSON())
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, rec.Code)
	}
}

func TestHealthz(t *testing.T) {
	handler := mustHandler(t, Config{DetectionWebhookToken: testWebhookToken}, &fakeAlertSender{}, &fakeRotationService{})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, rec.Code)
	}
	if strings.TrimSpace(rec.Body.String()) != "ok" {
		t.Fatalf("expected ok body, got %q", rec.Body.String())
	}
}

func mustHandler(t *testing.T, config Config, sender *fakeAlertSender, rotationSvc *fakeRotationService) http.Handler {
	t.Helper()

	handler, err := NewHandler(Dependencies{
		Config:   config,
		Sender:   sender,
		Rotation: rotationSvc,
		Logger:   log.New(io.Discard, "", 0),
		Now:      fixedTime,
	})
	if err != nil {
		t.Fatalf("NewHandler returned error: %v", err)
	}
	return handler
}

func authenticatedRequest(method, target, body string) *http.Request {
	req := httptest.NewRequest(method, target, bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer "+testWebhookToken)
	return req
}

func validDetectionJSON() string {
	return `{
		"repository": "acme/tripwire",
		"branch": "main",
		"commit_sha": "abc1234def5678",
		"rule": "aws-access-key-id",
		"file_path": "config/settings.py",
		"author": "dev@example.com",
		"source": "github-actions",
		"detected_at": "2026-02-26T12:00:00Z"
	}`
}

func fixedTime() time.Time {
	return time.Date(2026, 2, 26, 12, 0, 0, 0, time.UTC)
}
