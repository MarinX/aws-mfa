// Package sts wraps AWS STS operations for obtaining short-term credentials.
// It explicitly constructs clients using only the provided long-term credentials
// and never touches the ambient credential chain or AWS_PROFILE.
package sts

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const (
	// MinDurationGetSessionToken is the minimum allowed duration for GetSessionToken.
	MinDurationGetSessionToken = 900
	// MaxDurationGetSessionToken is the maximum allowed duration for GetSessionToken.
	MaxDurationGetSessionToken = 129600

	// MinDurationAssumeRole is the minimum allowed duration for AssumeRole.
	MinDurationAssumeRole = 900
	// MaxDurationAssumeRole is the maximum allowed duration for AssumeRole.
	MaxDurationAssumeRole = 43200
)

// Credentials holds the short-term credentials returned by STS.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

// SessionTokenInput holds parameters for GetSessionToken.
type SessionTokenInput struct {
	AccessKeyID     string
	SecretAccessKey string
	MFADeviceARN    string
	MFAToken        string
	Duration        int32
	Region          string
}

// AssumeRoleInput holds parameters for AssumeRole.
type AssumeRoleInput struct {
	AccessKeyID     string
	SecretAccessKey string
	RoleARN         string
	SessionName     string
	ExternalID      string
	MFADeviceARN    string
	MFAToken        string
	Duration        int32
	Region          string
}

// ValidateSessionTokenDuration returns an error if duration is outside the
// allowed range for GetSessionToken (900–129600 seconds).
func ValidateSessionTokenDuration(duration int32) error {
	if duration < MinDurationGetSessionToken || duration > MaxDurationGetSessionToken {
		return fmt.Errorf(
			"duration %d is outside the allowed range for GetSessionToken (%d–%d seconds); "+
				"adjust --duration or the mfa_duration key in your long-term profile",
			duration, MinDurationGetSessionToken, MaxDurationGetSessionToken,
		)
	}
	return nil
}

// ValidateAssumeRoleDuration returns an error if duration is outside the
// allowed range for AssumeRole (900–43200 seconds).
func ValidateAssumeRoleDuration(duration int32) error {
	if duration < MinDurationAssumeRole || duration > MaxDurationAssumeRole {
		return fmt.Errorf(
			"duration %d is outside the allowed range for AssumeRole (%d–%d seconds); "+
				"adjust --duration or the mfa_duration key in your long-term profile",
			duration, MinDurationAssumeRole, MaxDurationAssumeRole,
		)
	}
	return nil
}

// newClient constructs an STS client explicitly using the provided long-term
// credentials. It never reads AWS_PROFILE or the default credential chain.
func newClient(accessKeyID, secretAccessKey, region string) *sts.Client {
	staticCreds := credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, "")
	cfg := aws.Config{
		Credentials: staticCreds,
		Region:      region,
	}
	return sts.NewFromConfig(cfg)
}

// GetSessionToken calls sts:GetSessionToken and returns short-term credentials.
func GetSessionToken(ctx context.Context, in SessionTokenInput) (Credentials, error) {
	if err := ValidateSessionTokenDuration(in.Duration); err != nil {
		return Credentials{}, err
	}

	client := newClient(in.AccessKeyID, in.SecretAccessKey, in.Region)

	input := &sts.GetSessionTokenInput{
		DurationSeconds: aws.Int32(in.Duration),
		SerialNumber:    aws.String(in.MFADeviceARN),
		TokenCode:       aws.String(in.MFAToken),
	}

	resp, err := client.GetSessionToken(ctx, input)
	if err != nil {
		return Credentials{}, fmt.Errorf("sts:GetSessionToken failed: %w", err)
	}
	if resp.Credentials == nil {
		return Credentials{}, fmt.Errorf("sts:GetSessionToken returned no credentials")
	}

	return Credentials{
		AccessKeyID:     aws.ToString(resp.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(resp.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(resp.Credentials.SessionToken),
		Expiration:      aws.ToTime(resp.Credentials.Expiration).UTC(),
	}, nil
}

// AssumeRole calls sts:AssumeRole and returns short-term credentials.
func AssumeRole(ctx context.Context, in AssumeRoleInput) (Credentials, error) {
	if err := ValidateAssumeRoleDuration(in.Duration); err != nil {
		return Credentials{}, err
	}

	client := newClient(in.AccessKeyID, in.SecretAccessKey, in.Region)

	input := &sts.AssumeRoleInput{
		RoleArn:         aws.String(in.RoleARN),
		RoleSessionName: aws.String(in.SessionName),
		DurationSeconds: aws.Int32(in.Duration),
		SerialNumber:    aws.String(in.MFADeviceARN),
		TokenCode:       aws.String(in.MFAToken),
	}
	if in.ExternalID != "" {
		input.ExternalId = aws.String(in.ExternalID)
	}

	resp, err := client.AssumeRole(ctx, input)
	if err != nil {
		return Credentials{}, fmt.Errorf("sts:AssumeRole failed: %w", err)
	}
	if resp.Credentials == nil {
		return Credentials{}, fmt.Errorf("sts:AssumeRole returned no credentials")
	}

	return Credentials{
		AccessKeyID:     aws.ToString(resp.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(resp.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(resp.Credentials.SessionToken),
		Expiration:      aws.ToTime(resp.Credentials.Expiration).UTC(),
	}, nil
}
