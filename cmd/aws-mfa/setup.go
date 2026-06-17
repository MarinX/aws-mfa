package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/MarinX/aws-mfa/internal/credentials"
)

func buildSetupCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "setup",
		Short: "Interactively create a long-term credential section",
		Long: `setup prompts for a profile name, AWS access key ID, and secret access key,
then writes the [profile-long-term] section to ~/.aws/credentials.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE:          runSetup,
	}
}

func runSetup(_ *cobra.Command, _ []string) error {
	reader := bufio.NewReader(os.Stdin)

	profileName, err := prompt(reader, "Profile name", "default")
	if err != nil {
		return err
	}
	accessKeyID, err := prompt(reader, "AWS Access Key ID", "")
	if err != nil {
		return err
	}
	if accessKeyID == "" {
		return fmt.Errorf("AWS Access Key ID cannot be empty")
	}
	secretAccessKey, err := prompt(reader, "AWS Secret Access Key", "")
	if err != nil {
		return err
	}
	if secretAccessKey == "" {
		return fmt.Errorf("AWS Secret Access Key cannot be empty")
	}

	credPath, err := credentials.DefaultPath()
	if err != nil {
		return err
	}
	if err = credentials.EnsureDir(credPath); err != nil {
		return err
	}

	f, err := credentials.Load(credPath)
	if err != nil {
		return err
	}

	section := profileName + "-long-term"
	if err := f.WriteSetupSection(section, accessKeyID, secretAccessKey); err != nil {
		return fmt.Errorf("cannot write section [%s]: %w", section, err)
	}

	fmt.Printf("Wrote long-term credentials to [%s] in %s\n", section, credPath)
	fmt.Printf("Run `aws-mfa --profile %s` to obtain short-term credentials.\n", profileName)
	return nil
}
