// Package credentials handles reading and writing AWS credentials files
// using the INI format. It provides surgical, comment-preserving updates
// by operating on the raw file bytes for the short-term section while
// using gopkg.in/ini.v1 for reads.
package credentials

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/ini.v1"
)

const (
	// KeyAccessKeyID is the AWS access key ID credential file key.
	KeyAccessKeyID = "aws_access_key_id"
	// KeySecretAccessKey is the AWS secret access key credential file key.
	KeySecretAccessKey = "aws_secret_access_key"
	// KeySessionToken is the AWS session token credential file key.
	KeySessionToken = "aws_session_token"
	// KeySecurityToken is the legacy boto2 security token key (same value as session token).
	KeySecurityToken = "aws_security_token"
	// KeyExpiration is the expiration timestamp key stored in RFC3339 UTC.
	KeyExpiration = "expiration"
	// KeyAssumedRole indicates whether the short-term credentials were obtained via AssumeRole.
	KeyAssumedRole = "assumed_role"
	// KeyAssumedRoleARN is the ARN of the role that was assumed.
	KeyAssumedRoleARN = "assumed_role_arn"

	// LongTermKeyMFADevice is the MFA device ARN stored in the long-term section.
	LongTermKeyMFADevice = "aws_mfa_device"
	// LongTermKeyAssumeRole is the role ARN stored in the long-term section.
	LongTermKeyAssumeRole = "assume_role"
	// LongTermKeyAssumeRoleSessionName is the session name stored in the long-term section.
	LongTermKeyAssumeRoleSessionName = "assume_role_session_name"
	// LongTermKeyExternalID is the external ID stored in the long-term section.
	LongTermKeyExternalID = "external_id"
	// LongTermKeyRegion is the AWS region stored in the long-term section.
	LongTermKeyRegion = "region"
	// LongTermKeyMFADuration is the duration stored in the long-term section.
	LongTermKeyMFADuration = "mfa_duration"
)

// File wraps access to an AWS credentials INI file.
type File struct {
	path string
	cfg  *ini.File
}

// DefaultPath returns the default path for the AWS credentials file.
// It respects AWS_SHARED_CREDENTIALS_FILE if set.
func DefaultPath() (string, error) {
	if v := os.Getenv("AWS_SHARED_CREDENTIALS_FILE"); v != "" {
		return v, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".aws", "credentials"), nil
}

// EnsureDir ensures the ~/.aws directory exists with permissions 0700.
func EnsureDir(credPath string) error {
	dir := filepath.Dir(credPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("cannot create directory %s: %w", dir, err)
	}
	return nil
}

// Load reads the credentials file from path. If the file does not exist
// it returns an empty File (not an error) so callers can check Exists().
func Load(path string) (*File, error) {
	opts := ini.LoadOptions{
		AllowBooleanKeys:    false,
		IgnoreInlineComment: true,
		AllowShadows:        false,
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		empty, _ := ini.LoadSources(opts, []byte(""))
		return &File{path: path, cfg: empty}, nil
	}

	cfg, err := ini.LoadSources(opts, path)
	if err != nil {
		return nil, fmt.Errorf("cannot parse credentials file %s: %w", path, err)
	}
	return &File{path: path, cfg: cfg}, nil
}

// Exists reports whether the credentials file exists on disk.
func (f *File) Exists() bool {
	_, err := os.Stat(f.path)
	return err == nil
}

// Path returns the file path.
func (f *File) Path() string {
	return f.path
}

// SectionExists reports whether a named section exists in the file.
func (f *File) SectionExists(name string) bool {
	return f.cfg.HasSection(name)
}

// GetKey returns the value of a key in a section, or "" if missing.
func (f *File) GetKey(section, key string) string {
	sec, err := f.cfg.GetSection(section)
	if err != nil {
		return ""
	}
	k, err := sec.GetKey(key)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(k.Value())
}

// HasRequiredShortTermKeys reports whether the short-term section has all
// keys required for valid short-term credentials.
func (f *File) HasRequiredShortTermKeys(section string) bool {
	required := []string{KeyAccessKeyID, KeySecretAccessKey, KeySessionToken, KeyExpiration}
	for _, k := range required {
		if f.GetKey(section, k) == "" {
			return false
		}
	}
	return true
}

// ParseExpiration parses the expiration value from the short-term section.
// Returns zero time and an error if the value is missing or unparseable.
func (f *File) ParseExpiration(section string) (time.Time, error) {
	raw := f.GetKey(section, KeyExpiration)
	if raw == "" {
		return time.Time{}, fmt.Errorf("section [%s] has no %q key", section, KeyExpiration)
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("cannot parse expiration %q: %w", raw, err)
	}
	return t.UTC(), nil
}

// WriteSetupSection writes initial long-term credentials to a section.
// It does not overwrite the file; it only sets the three keys within the section.
func (f *File) WriteSetupSection(section, accessKeyID, secretAccessKey string) error {
	sec, err := f.cfg.NewSection(section)
	if err != nil {
		// Section may already exist; get it instead.
		sec, err = f.cfg.GetSection(section)
		if err != nil {
			return fmt.Errorf("cannot access section [%s]: %w", section, err)
		}
	}
	mustSetKey(sec, KeyAccessKeyID, accessKeyID)
	mustSetKey(sec, KeySecretAccessKey, secretAccessKey)
	return f.save()
}

// ShortTermUpdate holds all values to write into the short-term section.
type ShortTermUpdate struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
	AssumedRole     bool
	AssumedRoleARN  string
}

// WriteShortTermSection surgically updates only the short-term section keys
// without disturbing comments or other sections. It reads the raw file bytes,
// replaces (or appends) lines within the target section, then writes back.
func (f *File) WriteShortTermSection(section string, u ShortTermUpdate) error {
	expirationStr := u.Expiration.UTC().Format(time.RFC3339)
	assumedRoleStr := "false"
	if u.AssumedRole {
		assumedRoleStr = "true"
	}

	updates := map[string]string{
		KeyAccessKeyID:    u.AccessKeyID,
		KeySecretAccessKey: u.SecretAccessKey,
		KeySessionToken:   u.SessionToken,
		KeySecurityToken:  u.SessionToken,
		KeyExpiration:     expirationStr,
		KeyAssumedRole:    assumedRoleStr,
	}
	if u.AssumedRole && u.AssumedRoleARN != "" {
		updates[KeyAssumedRoleARN] = u.AssumedRoleARN
	}

	// Read existing file bytes (or start empty).
	var raw []byte
	if f.Exists() {
		var err error
		raw, err = os.ReadFile(f.path)
		if err != nil {
			return fmt.Errorf("cannot read credentials file: %w", err)
		}
	}

	raw = surgicalUpdate(raw, section, updates)

	if err := os.WriteFile(f.path, raw, 0600); err != nil {
		return fmt.Errorf("cannot write credentials file: %w", err)
	}

	// Reload the in-memory representation so subsequent reads are consistent.
	opts := ini.LoadOptions{
		AllowBooleanKeys:    false,
		IgnoreInlineComment: true,
	}
	cfg, err := ini.LoadSources(opts, f.path)
	if err != nil {
		return fmt.Errorf("cannot reload credentials file after write: %w", err)
	}
	f.cfg = cfg
	return nil
}

// save writes the in-memory ini representation to disk (used for setup).
func (f *File) save() error {
	if err := EnsureDir(f.path); err != nil {
		return err
	}
	var buf bytes.Buffer
	if _, err := f.cfg.WriteTo(&buf); err != nil {
		return fmt.Errorf("cannot serialise credentials: %w", err)
	}
	if err := os.WriteFile(f.path, buf.Bytes(), 0600); err != nil {
		return fmt.Errorf("cannot write credentials file %s: %w", f.path, err)
	}
	return nil
}

func mustSetKey(sec *ini.Section, key, value string) {
	if sec.HasKey(key) {
		sec.Key(key).SetValue(value)
	} else {
		_, _ = sec.NewKey(key, value)
	}
}

// surgicalUpdate rewrites the raw INI bytes, setting the given key=value pairs
// inside [section]. Keys that already exist in the section are replaced in-place;
// keys that are missing are appended before the next section header (or EOF).
// All other content (comments, other sections) is preserved byte-for-byte.
func surgicalUpdate(raw []byte, section string, updates map[string]string) []byte {
	header := "[" + section + "]"
	lines := strings.Split(string(raw), "\n")

	// Track which keys we already wrote (replaced in-place).
	written := make(map[string]bool)

	// keyRE matches lines like: key = value or key=value (with optional spaces).
	keyRE := regexp.MustCompile(`(?i)^([a-z_][a-z0-9_]*)\s*=.*$`)

	inSection := false
	var out []string
	insertIdx := -1 // line index just before the next section header or EOF

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Detect section headers.
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			if inSection && insertIdx < 0 {
				// We're leaving our target section — record where to insert missing keys.
				insertIdx = i
			}
			inSection = trimmed == header
			out = append(out, line)
			continue
		}

		if inSection {
			m := keyRE.FindStringSubmatch(trimmed)
			if m != nil {
				key := strings.ToLower(m[1])
				if newVal, ok := updates[key]; ok {
					// Replace this line with the updated value.
					out = append(out, key+" = "+newVal)
					written[key] = true
					continue
				}
			}
		}
		out = append(out, line)
	}

	// If we were still in the section when we hit EOF, insertIdx == -1 means append.
	if inSection {
		insertIdx = len(out)
	}

	// Build lines for keys not yet written.
	var missing []string
	// Preserve a stable order.
	orderedKeys := []string{
		KeyAccessKeyID, KeySecretAccessKey, KeySessionToken,
		KeySecurityToken, KeyExpiration, KeyAssumedRole, KeyAssumedRoleARN,
	}
	for _, k := range orderedKeys {
		if v, ok := updates[k]; ok && !written[k] {
			missing = append(missing, k+" = "+v)
		}
	}

	if len(missing) == 0 {
		return []byte(strings.Join(out, "\n"))
	}

	// Section header not found at all — append a brand-new section.
	if insertIdx < 0 {
		// Ensure a blank line before new section if file is non-empty.
		result := strings.Join(out, "\n")
		if len(result) > 0 && !strings.HasSuffix(result, "\n") {
			result += "\n"
		}
		result += "\n" + header + "\n" + strings.Join(missing, "\n") + "\n"
		return []byte(result)
	}

	// Insert missing keys at insertIdx (before next section / at EOF).
	newOut := make([]string, 0, len(out)+len(missing))
	newOut = append(newOut, out[:insertIdx]...)
	newOut = append(newOut, missing...)
	newOut = append(newOut, out[insertIdx:]...)
	return []byte(strings.Join(newOut, "\n"))
}
