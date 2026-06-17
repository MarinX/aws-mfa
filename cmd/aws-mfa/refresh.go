package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/MarinX/aws-mfa/internal/credentials"
	iampkg "github.com/MarinX/aws-mfa/internal/iam"
	stspkg "github.com/MarinX/aws-mfa/internal/sts"
)

func runRefresh(cmd *cobra.Command, f *flags) error {
	logger := setupLogger(f.logLevel)

	credPath, err := credentials.DefaultPath()
	if err != nil {
		return err
	}
	logger.Debug("Using credentials file", "path", credPath)

	if err = credentials.EnsureDir(credPath); err != nil {
		return err
	}

	credFile, err := credentials.Load(credPath)
	if err != nil {
		return err
	}

	if !credFile.Exists() {
		fmt.Printf("Credentials file %s does not exist.\n", credPath)
		reader := bufio.NewReader(os.Stdin)
		answer, _ := prompt(reader, "Create it now? [y/N]", "N")
		if strings.ToLower(strings.TrimSpace(answer)) != "y" {
			return fmt.Errorf("credentials file not found; run `aws-mfa setup` to create it")
		}
		if err = os.WriteFile(credPath, []byte(""), 0o600); err != nil {
			return fmt.Errorf("cannot create credentials file %s: %w", credPath, err)
		}
		credFile, err = credentials.Load(credPath)
		if err != nil {
			return err
		}
	}

	profile := resolveString(
		getFlagString(cmd, "profile"),
		os.Getenv("AWS_PROFILE"),
		"default",
	)

	longTermSuffix := resolveString(
		getFlagString(cmd, "long-term-suffix"),
		os.Getenv("MFA_LONG_TERM_SUFFIX"),
		"long-term",
	)
	shortTermSuffix := resolveString(
		getFlagString(cmd, "short-term-suffix"),
		os.Getenv("MFA_SHORT_TERM_SUFFIX"),
		"",
	)

	longTermName := buildSectionName(profile, longTermSuffix)
	shortTermName := buildSectionName(profile, shortTermSuffix)

	if longTermName == shortTermName {
		return fmt.Errorf(
			"long-term section name %q and short-term section name %q must differ; "+
				"adjust --long-term-suffix or --short-term-suffix",
			longTermName, shortTermName,
		)
	}

	logger.Debug("Section names", "long-term", longTermName, "short-term", shortTermName)

	if !credFile.SectionExists(longTermName) {
		return fmt.Errorf(
			"section [%s] not found in %s; "+
				"run `aws-mfa setup` or manually add your long-term credentials",
			longTermName, credPath,
		)
	}

	ltAccessKeyID := credFile.GetKey(longTermName, credentials.KeyAccessKeyID)
	ltSecretKey := credFile.GetKey(longTermName, credentials.KeySecretAccessKey)

	if ltAccessKeyID == "" {
		return fmt.Errorf(
			"[%s] is missing %q; add your long-term IAM access key ID",
			longTermName, credentials.KeyAccessKeyID,
		)
	}
	if ltSecretKey == "" {
		return fmt.Errorf(
			"[%s] is missing %q; add your long-term IAM secret access key",
			longTermName, credentials.KeySecretAccessKey,
		)
	}

	assumeRole := resolveString(
		getFlagString(cmd, "assume-role"),
		os.Getenv("MFA_ASSUME_ROLE"),
		credFile.GetKey(longTermName, credentials.LongTermKeyAssumeRole),
	)

	externalID := resolveString(
		getFlagString(cmd, "external-id"),
		"",
		credFile.GetKey(longTermName, credentials.LongTermKeyExternalID),
	)

	roleSessionName := resolveString(
		getFlagString(cmd, "role-session-name"),
		os.Getenv("MFA_ASSUME_ROLE_SESSION_NAME"),
		credFile.GetKey(longTermName, credentials.LongTermKeyAssumeRoleSessionName),
		osUsername(),
	)

	region := resolveString(
		getFlagString(cmd, "region"),
		os.Getenv("AWS_DEFAULT_REGION"),
		credFile.GetKey(longTermName, credentials.LongTermKeyRegion),
		"us-east-1",
	)

	defaultDuration := int32(43200)
	if assumeRole != "" {
		defaultDuration = 3600
	}
	duration := resolveDuration(f, credFile, longTermName, defaultDuration)

	device := resolveString(
		getFlagString(cmd, "device"),
		os.Getenv("MFA_DEVICE"),
		credFile.GetKey(longTermName, credentials.LongTermKeyMFADevice),
	)

	logger.Debug("Resolved config",
		"profile", profile,
		"region", region,
		"assumeRole", assumeRole,
		"duration", duration,
		"device", device,
	)

	if device == "" {
		logger.Debug("No MFA device configured; attempting auto-discovery via iam:ListMFADevices")
		var discovered string
		discovered, err = iampkg.ListMFADevices(context.Background(), iampkg.ListMFADevicesInput{
			AccessKeyID:     ltAccessKeyID,
			SecretAccessKey: ltSecretKey,
			Region:          region,
		})
		if err != nil {
			return fmt.Errorf("MFA device auto-discovery failed: %w", err)
		}
		device = discovered
		logger.Debug("Auto-discovered MFA device", "arn", device)
	}

	if !f.force && credFile.SectionExists(shortTermName) {
		needsRefresh, reason := checkNeedsRefresh(credFile, shortTermName, assumeRole, logger)
		if !needsRefresh {
			exp, _ := credFile.ParseExpiration(shortTermName)
			remaining := time.Until(exp).Round(time.Second)
			fmt.Printf(
				"Credentials for [%s] are still valid until %s (%s remaining).\n",
				shortTermName,
				exp.In(time.Local).Format("2006-01-02 15:04:05 MST"),
				remaining,
			)
			return nil
		}
		logger.Debug("Credentials need refresh", "reason", reason)
	}

	token := f.token
	if token == "" {
		token, err = promptMFAToken(device)
		if err != nil {
			return err
		}
	}
	if !isValidMFAToken(token) {
		return fmt.Errorf(
			"MFA token %q is invalid; it must be exactly 6 digits (e.g. 123456)",
			token,
		)
	}

	ctx := context.Background()
	var stsCreds stspkg.Credentials

	if assumeRole != "" {
		logger.Debug("Calling sts:AssumeRole", "roleARN", assumeRole, "duration", duration)
		stsCreds, err = stspkg.AssumeRole(ctx, stspkg.AssumeRoleInput{
			AccessKeyID:     ltAccessKeyID,
			SecretAccessKey: ltSecretKey,
			RoleARN:         assumeRole,
			SessionName:     roleSessionName,
			ExternalID:      externalID,
			MFADeviceARN:    device,
			MFAToken:        token,
			Duration:        duration,
			Region:          region,
		})
	} else {
		logger.Debug("Calling sts:GetSessionToken", "duration", duration)
		stsCreds, err = stspkg.GetSessionToken(ctx, stspkg.SessionTokenInput{
			AccessKeyID:     ltAccessKeyID,
			SecretAccessKey: ltSecretKey,
			MFADeviceARN:    device,
			MFAToken:        token,
			Duration:        duration,
			Region:          region,
		})
	}
	if err != nil {
		return err
	}

	update := credentials.ShortTermUpdate{
		AccessKeyID:     stsCreds.AccessKeyID,
		SecretAccessKey: stsCreds.SecretAccessKey,
		SessionToken:    stsCreds.SessionToken,
		Expiration:      stsCreds.Expiration,
		AssumedRole:     assumeRole != "",
		AssumedRoleARN:  assumeRole,
	}

	if err := credFile.WriteShortTermSection(shortTermName, update); err != nil {
		return fmt.Errorf("cannot write short-term credentials: %w", err)
	}

	localExp := stsCreds.Expiration.In(time.Local)
	fmt.Printf(
		"Successfully refreshed credentials for [%s].\n"+
			"Credentials valid until %s (%.0f seconds from now).\n",
		shortTermName,
		localExp.Format("2006-01-02 15:04:05 MST"),
		time.Until(stsCreds.Expiration).Seconds(),
	)
	return nil
}

func checkNeedsRefresh(credFile *credentials.File, section, wantAssumeRole string, logger interface{ Debug(string, ...any) }) (bool, string) {
	if !credFile.HasRequiredShortTermKeys(section) {
		return true, "one or more required keys are missing from the short-term section"
	}

	currentAssumedRole := credFile.GetKey(section, credentials.KeyAssumedRole)
	wantingRole := wantAssumeRole != ""
	if wantingRole && currentAssumedRole != "true" {
		return true, "assumed_role changed to true"
	}
	if !wantingRole && currentAssumedRole == "true" {
		return true, "assumed_role changed to false"
	}

	if wantAssumeRole != "" {
		currentARN := credFile.GetKey(section, credentials.KeyAssumedRoleARN)
		if currentARN != wantAssumeRole {
			return true, fmt.Sprintf("assumed_role_arn changed from %q to %q", currentARN, wantAssumeRole)
		}
	}

	exp, err := credFile.ParseExpiration(section)
	if err != nil {
		return true, fmt.Sprintf("cannot parse expiration: %v", err)
	}

	if time.Now().UTC().After(exp) {
		return true, fmt.Sprintf("credentials expired at %s", exp.Format(time.RFC3339))
	}

	logger.Debug("Credentials still valid", "expiration", exp.Format(time.RFC3339))
	return false, ""
}
