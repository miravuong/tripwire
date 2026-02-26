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

type SlackText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type SlackBlock struct {
	Type string    `json:"type"`
	Text SlackText `json:"text"`
}

type SlackPayload struct {
	Text   string       `json:"text"`
	Blocks []SlackBlock `json:"blocks"`
}

func BuildSlackPayload(event Event) SlackPayload {
	shortSHA := event.CommitSHA
	if len(shortSHA) > 7 {
		shortSHA = shortSHA[:7]
	}

	summary := fmt.Sprintf(
		":rotating_light: Secret detected in %s on %s (%s)",
		event.Repository,
		event.Branch,
		shortSHA,
	)

	detail := fmt.Sprintf(
		"*Repo:* `%s`\n*Branch:* `%s`\n*Commit:* `%s`\n*Rule:* `%s`\n*File:* `%s`\n*Author:* `%s`\n*Detected:* `%s`",
		event.Repository,
		event.Branch,
		event.CommitSHA,
		event.Rule,
		event.FilePath,
		event.Author,
		event.DetectedAt.UTC().Format(time.RFC3339),
	)

	return SlackPayload{
		Text: summary,
		Blocks: []SlackBlock{
			{Type: "section", Text: SlackText{Type: "mrkdwn", Text: summary}},
			{Type: "section", Text: SlackText{Type: "mrkdwn", Text: detail}},
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

func (s *Sender) SendSlack(ctx context.Context, webhookURL string, event Event) error {
	if err := event.Validate(); err != nil {
		return fmt.Errorf("invalid event: %w", err)
	}
	return s.sendJSON(ctx, webhookURL, BuildSlackPayload(event))
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
