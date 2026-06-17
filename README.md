# aws-mfa

A fast, single-binary CLI tool that automates AWS MFA credential refresh. Written in Go.

Reads long-term IAM credentials from `~/.aws/credentials`, calls AWS STS with your MFA token, and writes the resulting short-term credentials back — so every AWS SDK and CLI tool picks them up automatically.

This is a Go rewrite of [broamski/aws-mfa](https://github.com/broamski/aws-mfa)

---

## Installation

**Via `go install`:**
```bash
go install github.com/MarinX/aws-mfa/cmd/aws-mfa@latest
```

**Pre-built binaries** (Linux, macOS, Windows) are available on the [Releases](https://github.com/MarinX/aws-mfa/releases) page.

**From source:**
```bash
git clone https://github.com/MarinX/aws-mfa
cd aws-mfa
go build -o aws-mfa ./cmd/aws-mfa
```

---

## Quick start

### 1. Add your long-term credentials

Run the interactive setup:

```bash
aws-mfa setup
```

```
Profile name [default]: myprofile
AWS Access Key ID: AKIAIOSFODNN7EXAMPLE
AWS Secret Access Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

Or add the section to `~/.aws/credentials` manually:

```ini
[default-long-term]
aws_access_key_id     = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
aws_mfa_device        = arn:aws:iam::123456789012:mfa/myuser
```

> Your MFA device ARN is found in the AWS Console under  
> **IAM → Users → [your user] → Security credentials → Multi-factor authentication (MFA)**

### 2. Get your 6-digit MFA token

Open your authenticator app (Google Authenticator, Authy, 1Password, etc.) and read the current code for your AWS account.

### 3. Refresh credentials

```bash
aws-mfa
```

```
Enter MFA token for arn:aws:iam::123456789012:mfa/myuser: 123456
Successfully refreshed credentials for [default].
Credentials valid until 2026-06-18 02:00:00 CEST (43200 seconds from now).
```

Short-term credentials are now in the `[default]` section of `~/.aws/credentials` and will be used automatically by the AWS CLI, SDKs, and any other AWS tooling.

---

## How it works

The tool maintains two sections per profile in `~/.aws/credentials`:

| Section | Purpose |
|---|---|
| `[default-long-term]` | Your permanent IAM access key — never used directly for API calls |
| `[default]` | Temporary STS credentials written by aws-mfa — expire after 12 hours by default |

On each run, the tool checks whether the short-term credentials are still valid. If they are, it exits immediately with the remaining time. If they are expired (or missing), it prompts for an MFA token, calls STS, and writes fresh credentials.

---

## Usage

```
aws-mfa [flags]
aws-mfa setup
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `--profile` | `default` | AWS profile name |
| `--device` | (auto) | MFA device ARN |
| `--token` | (prompt) | MFA token — skip interactive prompt |
| `--duration` | `43200` | Credential validity in seconds (`3600` when assuming a role) |
| `--assume-role` | — | IAM role ARN to assume via `sts:AssumeRole` |
| `--external-id` | — | ExternalId for cross-account `AssumeRole` |
| `--role-session-name` | OS username | Session name for `AssumeRole` |
| `--region` | `us-east-1` | AWS region for the STS endpoint |
| `--long-term-suffix` | `long-term` | Suffix for the long-term section (`none` = no suffix) |
| `--short-term-suffix` | (empty) | Suffix for the short-term section (`none` = no suffix) |
| `--force` | `false` | Refresh even if credentials are still valid |
| `--log-level` | `INFO` | Log verbosity: `DEBUG`, `INFO`, `WARN`, `ERROR` |

### Environment variables

Every flag can be set via an environment variable. CLI flags always take precedence.

| Variable | Equivalent flag |
|---|---|
| `AWS_PROFILE` | `--profile` |
| `AWS_DEFAULT_REGION` | `--region` |
| `AWS_SHARED_CREDENTIALS_FILE` | credentials file path |
| `MFA_DEVICE` | `--device` |
| `MFA_STS_DURATION` | `--duration` |
| `MFA_ASSUME_ROLE` | `--assume-role` |
| `MFA_ASSUME_ROLE_SESSION_NAME` | `--role-session-name` |
| `MFA_LONG_TERM_SUFFIX` | `--long-term-suffix` |
| `MFA_SHORT_TERM_SUFFIX` | `--short-term-suffix` |

---

## Common scenarios

### Named profile

```bash
aws-mfa --profile staging
```

Reads from `[staging-long-term]`, writes to `[staging]`.

### Assume a role

```bash
aws-mfa --assume-role arn:aws:iam::999999999999:role/DeployRole
```

Calls `sts:AssumeRole` instead of `sts:GetSessionToken`. Default duration is 1 hour.

### Cross-account role with ExternalId

```bash
aws-mfa \
  --assume-role arn:aws:iam::999999999999:role/DeployRole \
  --external-id MyExternalId
```

### GovCloud or China regions

```bash
aws-mfa --region us-gov-west-1
aws-mfa --region cn-north-1
```

### Non-interactive / CI scripting

```bash
aws-mfa --token 123456
# or
MFA_TOKEN=123456 aws-mfa --token "$MFA_TOKEN"
```

### Force refresh before credentials expire

```bash
aws-mfa --force
```

### Custom session duration

```bash
aws-mfa --duration 3600    # 1 hour
aws-mfa --duration 28800   # 8 hours
aws-mfa --duration 129600  # 36 hours (GetSessionToken max)
```

Valid ranges:
- `sts:GetSessionToken`: 900–129600 seconds
- `sts:AssumeRole`: 900–43200 seconds

---

## Per-profile defaults in `~/.aws/credentials`

You can store defaults directly in the long-term section to avoid repeating flags on every run. Precedence is always: **CLI flag > environment variable > credentials file > built-in default**.

```ini
[myprofile-long-term]
aws_access_key_id         = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key     = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# Optional — if omitted, auto-discovered via iam:ListMFADevices
aws_mfa_device            = arn:aws:iam::123456789012:mfa/myuser

# Regional STS endpoint
region                    = eu-west-1

# Custom duration (seconds)
mfa_duration              = 28800

# Role assumption defaults
assume_role               = arn:aws:iam::999999999999:role/MyRole
assume_role_session_name  = my-session
external_id               = MyExternalId
```

---

## What the credentials file looks like after a refresh

Comments and formatting in your credentials file are always preserved:

```ini
# This comment survives every aws-mfa run
[myprofile-long-term]
aws_access_key_id     = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
aws_mfa_device        = arn:aws:iam::123456789012:mfa/myuser

[myprofile]
aws_access_key_id     = ASIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYTEMPKEY
aws_session_token     = AQoXnyc4lcK4w...
aws_security_token    = AQoXnyc4lcK4w...
expiration            = 2026-06-18T02:00:00Z
assumed_role          = false
```

---

## MFA device auto-discovery

If `aws_mfa_device` is not set anywhere (credentials file, `--device` flag, or `MFA_DEVICE` env var), the tool calls `iam:ListMFADevices` using your long-term credentials and uses the result automatically. If your account has zero or more than one MFA device configured, it will print a clear error asking you to specify the ARN explicitly.

---

## Section naming

The default section names are `[profile-long-term]` (long-term) and `[profile]` (short-term). You can change the suffixes:

```bash
# Use [myprofile-lt] and [myprofile-st]
aws-mfa --profile myprofile --long-term-suffix lt --short-term-suffix st

# Use [myprofile] and [myprofile-temp] (no long-term suffix)
aws-mfa --profile myprofile --long-term-suffix none --short-term-suffix temp
```

---

## Building and releasing

Releases are built with [GoReleaser](https://goreleaser.com/). A tagged push produces binaries for Linux, macOS, and Windows (amd64 + arm64) attached to the GitHub Release.

```bash
# Local snapshot build
goreleaser build --snapshot --clean
```

---

## License

MIT
