package rotation

import (
	"context"
	"errors"
	"testing"
	"time"
)

type testProvider struct {
	name string
	err  error
}

func (p testProvider) Name() string { return p.name }

func (p testProvider) Rotate(_ context.Context, event DetectionEvent) (RotationResult, error) {
	if p.err != nil {
		return RotationResult{}, p.err
	}
	return RotationResult{
		Provider:     p.name,
		Status:       "rotated",
		CredentialID: event.Rule,
		RotatedAt:    time.Now().UTC(),
	}, nil
}

func validEvent() DetectionEvent {
	return DetectionEvent{
		Repository: "acme/tripwire",
		Branch:     "main",
		CommitSHA:  "1234567890abcdef",
		Rule:       "aws-access-key-id",
		FilePath:   "app/config.go",
		Author:     "dev@example.com",
		Source:     "github-actions",
		DetectedAt: time.Now().UTC(),
	}
}

func TestRotateAllSuccess(t *testing.T) {
	svc := NewService(testProvider{name: "p1"}, testProvider{name: "p2"})
	results, err := svc.RotateAll(context.Background(), validEvent())
	if err != nil {
		t.Fatalf("RotateAll returned error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
}

func TestRotateAllFailsWhenProviderFails(t *testing.T) {
	svc := NewService(testProvider{name: "p1"}, testProvider{name: "p2", err: errors.New("boom")})
	_, err := svc.RotateAll(context.Background(), validEvent())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestRotateAllRequiresProviders(t *testing.T) {
	svc := NewService()
	_, err := svc.RotateAll(context.Background(), validEvent())
	if err == nil {
		t.Fatal("expected error for no providers")
	}
}
