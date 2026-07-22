package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"main/rotation"
)

type fakeIAM struct {
	existing       []iamtypes.AccessKeyMetadata
	created        string
	listErr        error
	createErr      error
	updateErr      error
	deleteErr      error
	deactivatedIDs []string
	deletedIDs     []string
}

func (f *fakeIAM) ListAccessKeys(_ context.Context, _ *iam.ListAccessKeysInput, _ ...func(*iam.Options)) (*iam.ListAccessKeysOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make([]iamtypes.AccessKeyMetadata, len(f.existing))
	copy(out, f.existing)
	return &iam.ListAccessKeysOutput{AccessKeyMetadata: out}, nil
}

func (f *fakeIAM) CreateAccessKey(_ context.Context, in *iam.CreateAccessKeyInput, _ ...func(*iam.Options)) (*iam.CreateAccessKeyOutput, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	newID := f.created
	if newID == "" {
		newID = "AKIA_NEW"
	}
	return &iam.CreateAccessKeyOutput{
		AccessKey: &iamtypes.AccessKey{
			UserName:    in.UserName,
			AccessKeyId: awssdk.String(newID),
			Status:      iamtypes.StatusTypeActive,
		},
	}, nil
}

func (f *fakeIAM) UpdateAccessKey(_ context.Context, in *iam.UpdateAccessKeyInput, _ ...func(*iam.Options)) (*iam.UpdateAccessKeyOutput, error) {
	if f.updateErr != nil {
		return nil, f.updateErr
	}
	f.deactivatedIDs = append(f.deactivatedIDs, awssdk.ToString(in.AccessKeyId))
	return &iam.UpdateAccessKeyOutput{}, nil
}

func (f *fakeIAM) DeleteAccessKey(_ context.Context, in *iam.DeleteAccessKeyInput, _ ...func(*iam.Options)) (*iam.DeleteAccessKeyOutput, error) {
	if f.deleteErr != nil {
		return nil, f.deleteErr
	}
	f.deletedIDs = append(f.deletedIDs, awssdk.ToString(in.AccessKeyId))
	return &iam.DeleteAccessKeyOutput{}, nil
}

func awsEvent() rotation.DetectionEvent {
	return rotation.DetectionEvent{
		Repository: "acme/tripwire",
		Branch:     "main",
		CommitSHA:  "1234567890abcdef",
		Rule:       "aws-access-key-id",
		FilePath:   "config/settings.py",
		Author:     "dev@example.com",
		Source:     "github-actions",
		DetectedAt: time.Now().UTC(),
	}
}

func newProvider(t *testing.T, fake *fakeIAM) *Provider {
	t.Helper()
	p, err := NewProviderWithClient(fake, Config{IAMUser: "tripwire-svc"})
	if err != nil {
		t.Fatalf("NewProviderWithClient: %v", err)
	}
	return p
}

func TestNewProviderRequiresIAMUser(t *testing.T) {
	if _, err := NewProviderWithClient(&fakeIAM{}, Config{}); err == nil {
		t.Fatal("expected error when IAMUser is empty")
	}
}

func TestNewProviderRequiresClient(t *testing.T) {
	if _, err := NewProviderWithClient(nil, Config{IAMUser: "u"}); err == nil {
		t.Fatal("expected error when IAM client is nil")
	}
}

func TestRotateHappyPathReplacesExistingKey(t *testing.T) {
	oldKey := iamtypes.AccessKeyMetadata{
		AccessKeyId: awssdk.String("AKIA_OLD"),
		Status:      iamtypes.StatusTypeActive,
		CreateDate:  awssdk.Time(time.Now().Add(-30 * 24 * time.Hour)),
	}
	fake := &fakeIAM{existing: []iamtypes.AccessKeyMetadata{oldKey}, created: "AKIA_NEW"}
	p := newProvider(t, fake)

	result, err := p.Rotate(context.Background(), awsEvent())
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if result.Status != "rotated" {
		t.Errorf("status = %q, want %q", result.Status, "rotated")
	}
	if result.CredentialID != "AKIA_NEW" {
		t.Errorf("CredentialID = %q, want %q", result.CredentialID, "AKIA_NEW")
	}
	if len(fake.deactivatedIDs) != 1 || fake.deactivatedIDs[0] != "AKIA_OLD" {
		t.Errorf("deactivated = %v, want [AKIA_OLD]", fake.deactivatedIDs)
	}
	if len(fake.deletedIDs) != 1 || fake.deletedIDs[0] != "AKIA_OLD" {
		t.Errorf("deleted = %v, want [AKIA_OLD]", fake.deletedIDs)
	}
}

func TestRotateFreshUserSkipsDeletion(t *testing.T) {
	fake := &fakeIAM{created: "AKIA_FRESH"}
	p := newProvider(t, fake)

	result, err := p.Rotate(context.Background(), awsEvent())
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if result.CredentialID != "AKIA_FRESH" {
		t.Errorf("CredentialID = %q, want %q", result.CredentialID, "AKIA_FRESH")
	}
	if len(fake.deletedIDs) != 0 {
		t.Errorf("deleted = %v, want none", fake.deletedIDs)
	}
	if len(fake.deactivatedIDs) != 0 {
		t.Errorf("deactivated = %v, want none", fake.deactivatedIDs)
	}
}

func TestRotateAtKeyLimitDeletesOldestFirst(t *testing.T) {
	older := iamtypes.AccessKeyMetadata{
		AccessKeyId: awssdk.String("AKIA_OLDER"),
		Status:      iamtypes.StatusTypeInactive,
		CreateDate:  awssdk.Time(time.Now().Add(-60 * 24 * time.Hour)),
	}
	newer := iamtypes.AccessKeyMetadata{
		AccessKeyId: awssdk.String("AKIA_NEWER"),
		Status:      iamtypes.StatusTypeActive,
		CreateDate:  awssdk.Time(time.Now().Add(-10 * 24 * time.Hour)),
	}
	fake := &fakeIAM{existing: []iamtypes.AccessKeyMetadata{newer, older}, created: "AKIA_NEW"}
	p := newProvider(t, fake)

	if _, err := p.Rotate(context.Background(), awsEvent()); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if len(fake.deletedIDs) != 2 {
		t.Fatalf("deleted = %v, want 2 entries", fake.deletedIDs)
	}
	if fake.deletedIDs[0] != "AKIA_OLDER" {
		t.Errorf("first delete = %q, want AKIA_OLDER", fake.deletedIDs[0])
	}
	if fake.deletedIDs[1] != "AKIA_NEWER" {
		t.Errorf("second delete = %q, want AKIA_NEWER", fake.deletedIDs[1])
	}
	// Older key was already Inactive, so it should not be deactivated again.
	if len(fake.deactivatedIDs) != 1 || fake.deactivatedIDs[0] != "AKIA_NEWER" {
		t.Errorf("deactivated = %v, want [AKIA_NEWER]", fake.deactivatedIDs)
	}
}

func TestRotateSkipsWhenRuleDoesNotMatchPrefix(t *testing.T) {
	fake := &fakeIAM{}
	p := newProvider(t, fake)

	event := awsEvent()
	event.Rule = "slack-webhook"

	result, err := p.Rotate(context.Background(), event)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if result.Status != "skipped" {
		t.Errorf("status = %q, want %q", result.Status, "skipped")
	}
	if len(fake.deletedIDs) != 0 || len(fake.deactivatedIDs) != 0 {
		t.Error("no IAM mutations should occur when rule is skipped")
	}
}

func TestRotateSkipsWhenRuleEmpty(t *testing.T) {
	fake := &fakeIAM{}
	p := newProvider(t, fake)

	event := awsEvent()
	event.Rule = ""

	result, err := p.Rotate(context.Background(), event)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if result.Status != "skipped" {
		t.Errorf("status = %q, want %q", result.Status, "skipped")
	}
}

func TestRotateHonorsCustomRulePrefixes(t *testing.T) {
	fake := &fakeIAM{created: "AKIA_NEW"}
	p, err := NewProviderWithClient(fake, Config{
		IAMUser:      "svc",
		RulePrefixes: []string{"custom-"},
	})
	if err != nil {
		t.Fatalf("NewProviderWithClient: %v", err)
	}

	event := awsEvent()
	event.Rule = "custom-thing"
	result, err := p.Rotate(context.Background(), event)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if result.Status != "rotated" {
		t.Errorf("status = %q, want rotated", result.Status)
	}
}

func TestRotateListErrorPropagates(t *testing.T) {
	fake := &fakeIAM{listErr: errors.New("iam list boom")}
	p := newProvider(t, fake)
	if _, err := p.Rotate(context.Background(), awsEvent()); err == nil {
		t.Fatal("expected error when ListAccessKeys fails")
	}
}

func TestRotateCreateErrorPropagates(t *testing.T) {
	fake := &fakeIAM{createErr: errors.New("iam create boom")}
	p := newProvider(t, fake)
	if _, err := p.Rotate(context.Background(), awsEvent()); err == nil {
		t.Fatal("expected error when CreateAccessKey fails")
	}
}

func TestRotateDeleteErrorPropagates(t *testing.T) {
	fake := &fakeIAM{
		existing: []iamtypes.AccessKeyMetadata{{
			AccessKeyId: awssdk.String("AKIA_OLD"),
			Status:      iamtypes.StatusTypeInactive,
			CreateDate:  awssdk.Time(time.Now()),
		}},
		created:   "AKIA_NEW",
		deleteErr: errors.New("iam delete boom"),
	}
	p := newProvider(t, fake)
	if _, err := p.Rotate(context.Background(), awsEvent()); err == nil {
		t.Fatal("expected error when DeleteAccessKey fails")
	}
}
