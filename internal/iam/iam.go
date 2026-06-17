// Package iam wraps AWS IAM operations used for MFA device auto-discovery.
// Like the sts package, clients are always constructed from explicit credentials
// and never from the ambient credential chain or AWS_PROFILE.
package iam

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// ListMFADevicesInput holds the long-term credentials used to list MFA devices.
type ListMFADevicesInput struct {
	AccessKeyID     string
	SecretAccessKey string
	Region          string
}

// ListMFADevices calls iam:ListMFADevices using the provided long-term credentials
// and returns the single MFA device ARN assigned to the calling user.
//
// It returns an error if:
//   - Zero MFA devices are found (not enrolled)
//   - More than one MFA device is found (ambiguous — use --device to specify)
func ListMFADevices(ctx context.Context, in ListMFADevicesInput) (string, error) {
	staticCreds := credentials.NewStaticCredentialsProvider(in.AccessKeyID, in.SecretAccessKey, "")
	cfg := aws.Config{
		Credentials: staticCreds,
		Region:      in.Region,
	}
	client := iam.NewFromConfig(cfg)

	resp, err := client.ListMFADevices(ctx, &iam.ListMFADevicesInput{})
	if err != nil {
		return "", fmt.Errorf(
			"iam:ListMFADevices failed: %w\n"+
				"Ensure your long-term credentials have iam:ListMFADevices permission, "+
				"or specify your device ARN with --device",
			err,
		)
	}

	switch len(resp.MFADevices) {
	case 0:
		return "", fmt.Errorf(
			"no MFA devices found for your IAM user; "+
				"enroll an MFA device in the AWS console or specify one with --device",
		)
	case 1:
		return aws.ToString(resp.MFADevices[0].SerialNumber), nil
	default:
		var arns []string
		for _, d := range resp.MFADevices {
			arns = append(arns, aws.ToString(d.SerialNumber))
		}
		return "", fmt.Errorf(
			"found %d MFA devices — cannot auto-select; specify one with --device:\n  %v",
			len(resp.MFADevices), arns,
		)
	}
}
