// Package aws implements the AWS IAM access-key rotation provider.
//
// When a detection event fires for an AWS-family rule, the provider creates a
// new access key for a configured IAM user, then deactivates and deletes every
// pre-existing key so the leaked credential can no longer be used. The plaintext
// SecretAccessKey is never logged or returned; only the new AccessKeyId is
// surfaced via the RotationResult so downstream systems can pick it up.
package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"main/rotation"
)

const providerName = "aws-iam"

var defaultRulePrefixes = []string{"aws-"}

// Config controls which IAM user is rotated and which rules trigger it.
type Config struct {
	// IAMUser is the AWS IAM user whose access keys will be rotated.
	IAMUser string
	// RulePrefixes gates rotation to detection events whose Rule starts with
	// one of these prefixes. Defaults to {"aws-"} when empty.
	RulePrefixes []string
}

// IAMAPI captures the IAM operations the provider needs. Defined as an
// interface so tests can substitute a fake without hitting AWS.
type IAMAPI interface {
	ListAccessKeys(ctx context.Context, in *iam.ListAccessKeysInput, opts ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error)
	CreateAccessKey(ctx context.Context, in *iam.CreateAccessKeyInput, opts ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error)
	UpdateAccessKey(ctx context.Context, in *iam.UpdateAccessKeyInput, opts ...func(*iam.Options)) (*iam.UpdateAccessKeyOutput, error)
	DeleteAccessKey(ctx context.Context, in *iam.DeleteAccessKeyInput, opts ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error)
}

// Provider rotates IAM access keys for a single configured user.
type Provider struct {
	client       IAMAPI
	iamUser      string
	rulePrefixes []string
}

// NewProvider builds a Provider backed by a real IAM client using the AWS
// default credential chain (env vars, shared config, IMDS, etc.).
func NewProvider(ctx context.Context, cfg Config) (*Provider, error) {
	if strings.TrimSpace(cfg.IAMUser) == "" {
		return nil, errors.New("aws provider: IAMUser is required")
	}
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws provider: load default config: %w", err)
	}
	return NewProviderWithClient(iam.NewFromConfig(awsCfg), cfg)
}

// NewProviderWithClient builds a Provider with an injected IAM client. Used
// by tests to substitute a fake.
func NewProviderWithClient(client IAMAPI, cfg Config) (*Provider, error) {
	if client == nil {
		return nil, errors.New("aws provider: IAM client is required")
	}
	if strings.TrimSpace(cfg.IAMUser) == "" {
		return nil, errors.New("aws provider: IAMUser is required")
	}
	prefixes := cfg.RulePrefixes
	if len(prefixes) == 0 {
		prefixes = defaultRulePrefixes
	}
	return &Provider{
		client:       client,
		iamUser:      strings.TrimSpace(cfg.IAMUser),
		rulePrefixes: prefixes,
	}, nil
}

func (p *Provider) Name() string { return providerName }

// Rotate performs a two-step rotation: mint a new access key for the configured
// user, then deactivate + delete every previously existing key.
func (p *Provider) Rotate(ctx context.Context, event rotation.DetectionEvent) (rotation.RotationResult, error) {
	rule := strings.TrimSpace(event.Rule)
	if !p.ruleMatches(rule) {
		return rotation.RotationResult{
			Provider:  providerName,
			Status:    "skipped",
			Message:   fmt.Sprintf("rule %q not in allowed prefixes %v", rule, p.rulePrefixes),
			RotatedAt: time.Now().UTC(),
		}, nil
	}

	existing, err := p.client.ListAccessKeys(ctx, &iam.ListAccessKeysInput{
		UserName: awssdk.String(p.iamUser),
	})
	if err != nil {
		return rotation.RotationResult{}, fmt.Errorf("list access keys for %s: %w", p.iamUser, err)
	}

	// IAM allows at most two access keys per user. If the user is already at
	// the limit, delete one existing key before creating the replacement so
	// CreateAccessKey does not fail with LimitExceeded.
	if len(existing.AccessKeyMetadata) >= 2 {
		oldest := oldestKey(existing.AccessKeyMetadata)
		if err := p.deleteKey(ctx, oldest); err != nil {
			return rotation.RotationResult{}, err
		}
		existing.AccessKeyMetadata = removeKey(existing.AccessKeyMetadata, oldest)
	}

	created, err := p.client.CreateAccessKey(ctx, &iam.CreateAccessKeyInput{
		UserName: awssdk.String(p.iamUser),
	})
	if err != nil {
		return rotation.RotationResult{}, fmt.Errorf("create access key for %s: %w", p.iamUser, err)
	}
	if created.AccessKey == nil || created.AccessKey.AccessKeyId == nil {
		return rotation.RotationResult{}, errors.New("create access key returned no AccessKeyId")
	}
	newKeyID := awssdk.ToString(created.AccessKey.AccessKeyId)

	deleted := 0
	for _, meta := range existing.AccessKeyMetadata {
		if awssdk.ToString(meta.AccessKeyId) == newKeyID {
			continue
		}
		if err := p.deleteKey(ctx, meta); err != nil {
			return rotation.RotationResult{}, err
		}
		deleted++
	}

	return rotation.RotationResult{
		Provider:     providerName,
		Status:       "rotated",
		CredentialID: newKeyID,
		Message:      fmt.Sprintf("rotated %s: created 1 key, deleted %d prior keys", p.iamUser, deleted),
		RotatedAt:    time.Now().UTC(),
	}, nil
}

func (p *Provider) ruleMatches(rule string) bool {
	if rule == "" {
		return false
	}
	for _, prefix := range p.rulePrefixes {
		if strings.HasPrefix(rule, prefix) {
			return true
		}
	}
	return false
}

func (p *Provider) deleteKey(ctx context.Context, meta iamtypes.AccessKeyMetadata) error {
	keyID := awssdk.ToString(meta.AccessKeyId)
	if keyID == "" {
		return errors.New("cannot delete access key with empty AccessKeyId")
	}
	if meta.Status == iamtypes.StatusTypeActive {
		if _, err := p.client.UpdateAccessKey(ctx, &iam.UpdateAccessKeyInput{
			UserName:    awssdk.String(p.iamUser),
			AccessKeyId: awssdk.String(keyID),
			Status:      iamtypes.StatusTypeInactive,
		}); err != nil {
			return fmt.Errorf("deactivate access key %s: %w", keyID, err)
		}
	}
	if _, err := p.client.DeleteAccessKey(ctx, &iam.DeleteAccessKeyInput{
		UserName:    awssdk.String(p.iamUser),
		AccessKeyId: awssdk.String(keyID),
	}); err != nil {
		return fmt.Errorf("delete access key %s: %w", keyID, err)
	}
	return nil
}

func oldestKey(keys []iamtypes.AccessKeyMetadata) iamtypes.AccessKeyMetadata {
	oldest := keys[0]
	for _, k := range keys[1:] {
		if k.CreateDate != nil && (oldest.CreateDate == nil || k.CreateDate.Before(*oldest.CreateDate)) {
			oldest = k
		}
	}
	return oldest
}

func removeKey(keys []iamtypes.AccessKeyMetadata, target iamtypes.AccessKeyMetadata) []iamtypes.AccessKeyMetadata {
	targetID := awssdk.ToString(target.AccessKeyId)
	out := keys[:0]
	for _, k := range keys {
		if awssdk.ToString(k.AccessKeyId) == targetID {
			continue
		}
		out = append(out, k)
	}
	return out
}
