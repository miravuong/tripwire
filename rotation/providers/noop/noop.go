package noop

import (
	"context"
	"fmt"
	"strings"
	"time"

	"main/rotation"
)

// Provider is a safe default provider that logs simulated rotations.
type Provider struct{}

func NewProvider() *Provider {
	return &Provider{}
}

func (p *Provider) Name() string {
	return "noop"
}

func (p *Provider) Rotate(_ context.Context, event rotation.DetectionEvent) (rotation.RotationResult, error) {
	rule := strings.TrimSpace(event.Rule)
	if rule == "" {
		rule = "unknown-rule"
	}
	credentialID := fmt.Sprintf("%s:%s", rule, shortSHA(event.CommitSHA))
	return rotation.RotationResult{
		Provider:     p.Name(),
		Status:       "simulated",
		CredentialID: credentialID,
		Message:      "simulated rotation completed",
		RotatedAt:    time.Now().UTC(),
	}, nil
}

func shortSHA(sha string) string {
	sha = strings.TrimSpace(sha)
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}
