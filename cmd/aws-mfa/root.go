package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

type flags struct {
	device          string
	duration        int32
	profile         string
	longTermSuffix  string
	shortTermSuffix string
	assumeRole      string
	externalID      string
	roleSessionName string
	region          string
	force           bool
	token           string
	logLevel        string
}

func buildRootCmd(f *flags) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "aws-mfa",
		Short:   "Refresh AWS MFA short-term credentials",
		Version: version,
		Long: `aws-mfa automates refreshing AWS MFA short-term credentials.

It reads long-term IAM credentials from [profile-long-term] in ~/.aws/credentials,
calls AWS STS with an MFA token, and writes the resulting short-term credentials
back to [profile].`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRefresh(cmd, f)
		},
	}

	cmd.SetVersionTemplate(fmt.Sprintf("aws-mfa %s (commit: %s, built: %s)\n", version, commit, date))

	cmd.Flags().StringVar(&f.device, "device", "", "MFA device ARN (or set MFA_DEVICE env var)")
	cmd.Flags().Int32Var(&f.duration, "duration", 0,
		"Credential validity in seconds (default 43200 for GetSessionToken, 3600 for AssumeRole)")
	cmd.Flags().StringVar(&f.profile, "profile", "", "AWS profile name (default: $AWS_PROFILE or \"default\")")
	cmd.Flags().StringVar(&f.longTermSuffix, "long-term-suffix", "",
		"Suffix for long-term section (default \"long-term\"; use \"none\" for no suffix)")
	cmd.Flags().StringVar(&f.shortTermSuffix, "short-term-suffix", "",
		"Suffix for short-term section (use \"none\" for no suffix)")
	cmd.Flags().StringVar(&f.assumeRole, "assume-role", "", "IAM role ARN to assume via sts:AssumeRole")
	cmd.Flags().StringVar(&f.externalID, "external-id", "", "ExternalId for cross-account AssumeRole")
	cmd.Flags().StringVar(&f.roleSessionName, "role-session-name", "",
		"Session name for AssumeRole (default: OS username)")
	cmd.Flags().StringVar(&f.region, "region", "", "AWS region for STS endpoint")
	cmd.Flags().BoolVar(&f.force, "force", false, "Refresh even if credentials are still valid")
	cmd.Flags().StringVar(&f.token, "token", "", "MFA token (skip interactive prompt)")
	cmd.Flags().StringVar(&f.logLevel, "log-level", "INFO", "Log verbosity (DEBUG, INFO, WARN, ERROR)")

	return cmd
}
