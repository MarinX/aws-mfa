package main

import (
	"log/slog"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/MarinX/aws-mfa/internal/credentials"
)

func setupLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToUpper(level) {
	case "DEBUG":
		lvl = slog.LevelDebug
	case "WARN", "WARNING":
		lvl = slog.LevelWarn
	case "ERROR":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
	return slog.New(h)
}

func buildSectionName(profile, suffix string) string {
	if suffix == "" || strings.EqualFold(suffix, "none") {
		return profile
	}
	return profile + "-" + suffix
}

func resolveString(candidates ...string) string {
	for _, c := range candidates {
		if c != "" {
			return c
		}
	}
	return ""
}

func resolveDuration(f *flags, credFile *credentials.File, longTermName string, defaultVal int32) int32 {
	if f.duration != 0 {
		return f.duration
	}
	if v := os.Getenv("MFA_STS_DURATION"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 32); err == nil && n > 0 {
			return int32(n)
		}
	}
	if v := credFile.GetKey(longTermName, credentials.LongTermKeyMFADuration); v != "" {
		if n, err := strconv.ParseInt(v, 10, 32); err == nil && n > 0 {
			return int32(n)
		}
	}
	return defaultVal
}

// getFlagString returns the string value of a flag only if it was explicitly
// set by the user, so that unset flags don't shadow env vars.
func getFlagString(cmd *cobra.Command, name string) string {
	if cmd.Flags().Changed(name) {
		v, _ := cmd.Flags().GetString(name)
		return v
	}
	return ""
}

func osUsername() string {
	u, err := user.Current()
	if err != nil {
		return "aws-mfa-session"
	}
	return u.Username
}
