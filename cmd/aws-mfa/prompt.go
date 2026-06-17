package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

func promptMFAToken(deviceARN string) (string, error) {
	if deviceARN != "" {
		fmt.Printf("Enter MFA token for %s: ", deviceARN)
	} else {
		fmt.Print("Enter MFA token: ")
	}
	reader := bufio.NewReader(os.Stdin)
	token, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("cannot read MFA token: %w", err)
	}
	return strings.TrimSpace(token), nil
}

func isValidMFAToken(token string) bool {
	matched, _ := regexp.MatchString(`^\d{6}$`, token)
	return matched
}

func prompt(reader *bufio.Reader, message, defaultVal string) (string, error) {
	if defaultVal != "" {
		fmt.Printf("%s [%s]: ", message, defaultVal)
	} else {
		fmt.Printf("%s: ", message)
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("cannot read input: %w", err)
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return defaultVal, nil
	}
	return line, nil
}
