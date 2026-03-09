package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Event contains non-secret metadata about a leaked credential finding.
type Event struct {
	Repository string    `json:"repository"`
	Branch     string    `json:"branch"`
	CommitSHA  string    `json:"commit_sha"`
	Rule       string    `json:"rule"`
	FilePath   string    `json:"file_path"`
	Author     string    `json:"author"`
	DetectedAt time.Time `json:"detected_at"`
}

func (e Event) Validate() error {
	if strings.TrimSpace(e.Repository) == "" {
		return errors.New("repository is required")
	}
	if strings.TrimSpace(e.Branch) == "" {
		return errors.New("branch is required")
	}
	if strings.TrimSpace(e.CommitSHA) == "" {
		return errors.New("commit_sha is required")
	}
	if strings.TrimSpace(e.Rule) == "" {
		return errors.New("rule is required")
	}
	if strings.TrimSpace(e.FilePath) == "" {
		return errors.New("file_path is required")
	}
	if strings.TrimSpace(e.Author) == "" {
		return errors.New("author is required")
	}
	if e.DetectedAt.IsZero() {
		return errors.New("detected_at is required")
	}
	return nil
}

// DiscordEmbed represents a Discord rich embed object.
type DiscordEmbed struct {
	Title       string              `json:"title"`
	Description string              `json:"description"`
	Color       int                 `json:"color"`
	Fields      []DiscordEmbedField `json:"fields"`
	Timestamp   string              `json:"timestamp,omitempty"`
}

// DiscordEmbedField represents a field inside a Discord embed.
type DiscordEmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

// DiscordPayload represents the JSON body sent to a Discord webhook.
type DiscordPayload struct {
	Content string         `json:"content"`
	Embeds  []DiscordEmbed `json:"embeds"`
}

func BuildDiscordPayload(event Event) DiscordPayload {
	shortSHA := event.CommitSHA
	if len(shortSHA) > 7 {
		shortSHA = shortSHA[:7]
	}

	summary := fmt.Sprintf("🚨 Secret detected in %s on %s (%s)", event.Repository, event.Branch, shortSHA)

	return DiscordPayload{
		Content: summary,
		Embeds: []DiscordEmbed{
			{
				Title:       "Secret Leak Detected",
				Description: summary,
				Color:       0xFF0000,
				Fields: []DiscordEmbedField{
					{Name: "Repository", Value: fmt.Sprintf("`%s`", event.Repository), Inline: true},
					{Name: "Branch", Value: fmt.Sprintf("`%s`", event.Branch), Inline: true},
					{Name: "Commit", Value: fmt.Sprintf("`%s`", event.CommitSHA), Inline: false},
					{Name: "Rule", Value: fmt.Sprintf("`%s`", event.Rule), Inline: true},
					{Name: "File", Value: fmt.Sprintf("`%s`", event.FilePath), Inline: true},
					{Name: "Author", Value: fmt.Sprintf("`%s`", event.Author), Inline: true},
					{Name: "Detected At", Value: fmt.Sprintf("`%s`", event.DetectedAt.UTC().Format(time.RFC3339)), Inline: false},
				},
				Timestamp: event.DetectedAt.UTC().Format(time.RFC3339),
			},
		},
	}
}

type WebhookPayload struct {
	Event      string `json:"event"`
	Repository string `json:"repository"`
	Branch     string `json:"branch"`
	CommitSHA  string `json:"commit_sha"`
	Rule       string `json:"rule"`
	FilePath   string `json:"file_path"`
	Author     string `json:"author"`
	DetectedAt string `json:"detected_at"`
}

func BuildWebhookPayload(event Event) WebhookPayload {
	return WebhookPayload{
		Event:      "secret.detected",
		Repository: event.Repository,
		Branch:     event.Branch,
		CommitSHA:  event.CommitSHA,
		Rule:       event.Rule,
		FilePath:   event.FilePath,
		Author:     event.Author,
		DetectedAt: event.DetectedAt.UTC().Format(time.RFC3339),
	}
}

type Sender struct {
	Client *http.Client
}

func NewSender(client *http.Client) *Sender {
	if client == nil {
		client = http.DefaultClient
	}
	return &Sender{Client: client}
}

func (s *Sender) SendDiscord(ctx context.Context, webhookURL string, event Event) error {
	if err := event.Validate(); err != nil {
		return fmt.Errorf("invalid event: %w", err)
	}
	return s.sendJSON(ctx, webhookURL, BuildDiscordPayload(event))
}

func (s *Sender) SendWebhook(ctx context.Context, webhookURL string, event Event) error {
	if err := event.Validate(); err != nil {
		return fmt.Errorf("invalid event: %w", err)
	}
	return s.sendJSON(ctx, webhookURL, BuildWebhookPayload(event))
}

func (s *Sender) sendJSON(ctx context.Context, webhookURL string, payload any) error {
	if strings.TrimSpace(webhookURL) == "" {
		return errors.New("webhook URL is required")
	}
	if _, err := url.ParseRequestURI(webhookURL); err != nil {
		return fmt.Errorf("invalid webhook URL: %w", err)
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.Client.Do(req)
	if err != nil {
		return fmt.Errorf("send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}
