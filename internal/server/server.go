package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"main/alerting"
	"main/rotation"
)

const (
	DefaultListenAddr     = ":8080"
	MaxDetectionBodyBytes = 1 << 20

	bearerPrefix = "Bearer "
)

type Config struct {
	ListenAddr             string
	DetectionWebhookToken  string
	DiscordWebhookURL      string
	SlackWebhookURL        string
	GenericAlertWebhookURL string
}

func LoadConfigFromEnv() (Config, error) {
	config := Config{
		ListenAddr:             strings.TrimSpace(os.Getenv("LISTEN_ADDR")),
		DetectionWebhookToken:  strings.TrimSpace(os.Getenv("TRIPWIRE_WEBHOOK_TOKEN")),
		DiscordWebhookURL:      strings.TrimSpace(os.Getenv("DISCORD_WEBHOOK_URL")),
		SlackWebhookURL:        strings.TrimSpace(os.Getenv("SLACK_WEBHOOK_URL")),
		GenericAlertWebhookURL: strings.TrimSpace(os.Getenv("ALERT_WEBHOOK_URL")),
	}
	if config.ListenAddr == "" {
		config.ListenAddr = DefaultListenAddr
	}
	if config.DetectionWebhookToken == "" {
		return Config{}, errors.New("TRIPWIRE_WEBHOOK_TOKEN environment variable is required")
	}
	return config, nil
}

type AlertSender interface {
	SendDiscord(ctx context.Context, webhookURL string, event alerting.Event) error
	SendSlack(ctx context.Context, webhookURL string, event alerting.Event) error
	SendWebhook(ctx context.Context, webhookURL string, event alerting.Event) error
}

type RotationService interface {
	RotateAll(ctx context.Context, event rotation.DetectionEvent) ([]rotation.RotationResult, error)
}

type Dependencies struct {
	Config   Config
	Sender   AlertSender
	Rotation RotationService
	Logger   *log.Logger
	Now      func() time.Time
}

type app struct {
	config   Config
	sender   AlertSender
	rotation RotationService
	logger   *log.Logger
	now      func() time.Time
}

func NewHandler(deps Dependencies) (http.Handler, error) {
	app, err := newApp(deps)
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", app.handleHealth)
	mux.HandleFunc("/webhook/detection", app.handleDetectionWebhook)
	return mux, nil
}

func newApp(deps Dependencies) (*app, error) {
	config := deps.Config
	if strings.TrimSpace(config.DetectionWebhookToken) == "" {
		return nil, errors.New("detection webhook token is required")
	}
	if deps.Sender == nil {
		return nil, errors.New("alert sender is required")
	}
	if deps.Rotation == nil {
		return nil, errors.New("rotation service is required")
	}

	logger := deps.Logger
	if logger == nil {
		logger = log.Default()
	}
	now := deps.Now
	if now == nil {
		now = func() time.Time {
			return time.Now().UTC()
		}
	}

	return &app{
		config:   config,
		sender:   deps.Sender,
		rotation: deps.Rotation,
		logger:   logger,
		now:      now,
	}, nil
}

func (app *app) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "ok")
}

func (app *app) handleDetectionWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !app.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	event, err := app.decodeDetectionEvent(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	results, err := app.rotation.RotateAll(r.Context(), event)
	if err != nil {
		app.logger.Printf("rotation failed: %v", err)
		http.Error(w, "rotation failed", http.StatusInternalServerError)
		return
	}

	alertEvent := alerting.Event{
		Repository: event.Repository,
		Branch:     event.Branch,
		CommitSHA:  event.CommitSHA,
		Rule:       fallback(event.Rule, "unknown"),
		FilePath:   fallback(event.FilePath, "unknown"),
		Author:     fallback(event.Author, "unknown"),
		DetectedAt: event.DetectedAt,
	}

	if app.config.DiscordWebhookURL != "" {
		if err := app.sender.SendDiscord(r.Context(), app.config.DiscordWebhookURL, alertEvent); err != nil {
			app.logger.Printf("discord alert dispatch failed: %v", err)
			http.Error(w, "discord alert dispatch failed", http.StatusInternalServerError)
			return
		}
	}

	if app.config.SlackWebhookURL != "" {
		if err := app.sender.SendSlack(r.Context(), app.config.SlackWebhookURL, alertEvent); err != nil {
			app.logger.Printf("slack alert dispatch failed: %v", err)
			http.Error(w, "slack alert dispatch failed", http.StatusInternalServerError)
			return
		}
	}

	if app.config.GenericAlertWebhookURL != "" {
		if err := app.sender.SendWebhook(r.Context(), app.config.GenericAlertWebhookURL, alertEvent); err != nil {
			app.logger.Printf("generic webhook dispatch failed: %v", err)
			http.Error(w, "webhook alert dispatch failed", http.StatusInternalServerError)
			return
		}
	}

	response := map[string]any{
		"status":           "accepted",
		"rotations_count":  len(results),
		"rotation_results": results,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		app.logger.Printf("encode response failed: %v", err)
		return
	}
}

func (app *app) authorized(r *http.Request) bool {
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		return false
	}

	gotToken := strings.TrimSpace(strings.TrimPrefix(authHeader, bearerPrefix))
	wantToken := strings.TrimSpace(app.config.DetectionWebhookToken)
	if gotToken == "" || wantToken == "" {
		return false
	}
	gotHash := sha256.Sum256([]byte(gotToken))
	wantHash := sha256.Sum256([]byte(wantToken))
	return subtle.ConstantTimeCompare(gotHash[:], wantHash[:]) == 1
}

func (app *app) decodeDetectionEvent(r *http.Request) (rotation.DetectionEvent, error) {
	event := rotation.DetectionEvent{
		Repository: strings.TrimSpace(r.Header.Get("X-Repository")),
		Branch:     strings.TrimSpace(r.Header.Get("X-Branch")),
		CommitSHA:  strings.TrimSpace(r.Header.Get("X-Commit-SHA")),
		Rule:       strings.TrimSpace(r.Header.Get("X-Rule")),
		FilePath:   strings.TrimSpace(r.Header.Get("X-File-Path")),
		Author:     strings.TrimSpace(r.Header.Get("X-Author")),
		Source:     "http-header",
		DetectedAt: app.now(),
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, MaxDetectionBodyBytes+1))
	if err != nil {
		return rotation.DetectionEvent{}, fmt.Errorf("read request body: %w", err)
	}
	if int64(len(body)) > MaxDetectionBodyBytes {
		return rotation.DetectionEvent{}, fmt.Errorf("request body exceeds %d bytes", MaxDetectionBodyBytes)
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		if err := event.Validate(); err != nil {
			return rotation.DetectionEvent{}, fmt.Errorf("invalid detection event: %w", err)
		}
		return event, nil
	}

	var payload rotation.DetectionEvent
	if err := json.Unmarshal(body, &payload); err != nil {
		return rotation.DetectionEvent{}, fmt.Errorf("invalid JSON payload: %w", err)
	}

	payload.Repository = fallback(payload.Repository, event.Repository)
	payload.Branch = fallback(payload.Branch, event.Branch)
	payload.CommitSHA = fallback(payload.CommitSHA, event.CommitSHA)
	payload.Rule = fallback(payload.Rule, event.Rule)
	payload.FilePath = fallback(payload.FilePath, event.FilePath)
	payload.Author = fallback(payload.Author, event.Author)
	payload.Source = fallback(payload.Source, "github-actions")
	if payload.DetectedAt.IsZero() {
		payload.DetectedAt = app.now()
	}

	if err := payload.Validate(); err != nil {
		return rotation.DetectionEvent{}, fmt.Errorf("invalid detection event: %w", err)
	}
	return payload, nil
}

func fallback(primary, secondary string) string {
	if strings.TrimSpace(primary) != "" {
		return strings.TrimSpace(primary)
	}
	return strings.TrimSpace(secondary)
}
