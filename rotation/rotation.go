package rotation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DetectionEvent contains metadata about a secret finding.
type DetectionEvent struct {
	Repository string    `json:"repository"`
	Branch     string    `json:"branch"`
	CommitSHA  string    `json:"commit_sha"`
	Rule       string    `json:"rule"`
	FilePath   string    `json:"file_path"`
	Author     string    `json:"author"`
	Source     string    `json:"source"`
	DetectedAt time.Time `json:"detected_at"`
}

func (e DetectionEvent) Validate() error {
	if strings.TrimSpace(e.Repository) == "" {
		return errors.New("repository is required")
	}
	if strings.TrimSpace(e.Branch) == "" {
		return errors.New("branch is required")
	}
	if strings.TrimSpace(e.CommitSHA) == "" {
		return errors.New("commit_sha is required")
	}
	if e.DetectedAt.IsZero() {
		return errors.New("detected_at is required")
	}
	return nil
}

// RotationResult captures one provider rotation outcome.
type RotationResult struct {
	Provider     string    `json:"provider"`
	Status       string    `json:"status"`
	CredentialID string    `json:"credential_id,omitempty"`
	Message      string    `json:"message,omitempty"`
	RotatedAt    time.Time `json:"rotated_at"`
}

// Provider implements provider-specific rotation logic.
type Provider interface {
	Name() string
	Rotate(ctx context.Context, event DetectionEvent) (RotationResult, error)
}

// Service executes rotation providers for a detection event.
type Service struct {
	providers []Provider
}

func NewService(providers ...Provider) *Service {
	clean := make([]Provider, 0, len(providers))
	for _, p := range providers {
		if p != nil {
			clean = append(clean, p)
		}
	}
	return &Service{providers: clean}
}

func (s *Service) RotateAll(ctx context.Context, event DetectionEvent) ([]RotationResult, error) {
	if err := event.Validate(); err != nil {
		return nil, fmt.Errorf("validate event: %w", err)
	}
	if len(s.providers) == 0 {
		return nil, errors.New("no rotation providers configured")
	}

	results := make([]RotationResult, 0, len(s.providers))
	for _, provider := range s.providers {
		result, err := provider.Rotate(ctx, event)
		if err != nil {
			return nil, fmt.Errorf("%s rotation failed: %w", provider.Name(), err)
		}
		if result.Provider == "" {
			result.Provider = provider.Name()
		}
		if result.RotatedAt.IsZero() {
			result.RotatedAt = time.Now().UTC()
		}
		if strings.TrimSpace(result.Status) == "" {
			result.Status = "rotated"
		}
		results = append(results, result)
	}
	return results, nil
}
