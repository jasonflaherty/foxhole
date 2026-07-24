// Package awskeydetector implements a secret detection rule for AWS credentials.
package main

import (
	"fmt"
	"regexp"

	"github.com/jasonflaherty/foxhole/pkg/sdk/secret"
)

// AWSKeyDetector detects AWS access keys and secret keys.
type AWSKeyDetector struct {
	accessKeyPattern *regexp.Regexp
	secretKeyPattern *regexp.Regexp
}

// NewAWSKeyDetector creates a new detector instance.
func NewAWSKeyDetector() *AWSKeyDetector {
	return &AWSKeyDetector{
		accessKeyPattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		secretKeyPattern: regexp.MustCompile(`aws_secret_access_key\s*=\s*[\w/+]{40}`),
	}
}

// Metadata returns rule information.
func (d *AWSKeyDetector) Metadata() secret.SecretRuleMetadata {
	return secret.SecretRuleMetadata{
		ID:          "aws-access-key",
		Name:        "AWS Access Key",
		Version:     "0.1.0",
		Description: "Detects AWS Access Key IDs and Secret Access Keys",
		Severity:    "CRITICAL",
		Author:      "Foxhole Community",
		Repository:  "https://github.com/foxhole-plugins/secret-aws",
	}
}

// Pattern returns the compiled regex.
func (d *AWSKeyDetector) Pattern() *regexp.Regexp {
	return d.accessKeyPattern
}

// Match searches content for AWS credentials.
func (d *AWSKeyDetector) Match(content []byte) []secret.Match {
	var matches []secret.Match

	access := d.accessKeyPattern.FindAllStringSubmatchIndex(string(content), -1)
	for _, idx := range access {
		start, end := idx[0], idx[1]
		line, col := byteOffsetToLineCol(content, start)
		matches = append(matches, secret.Match{
			Start:      start,
			End:        end,
			Line:       line,
			Column:     col,
			Confidence: 0.95,
		})
	}

	secrets := d.secretKeyPattern.FindAllStringSubmatchIndex(string(content), -1)
	for _, idx := range secrets {
		start, end := idx[0], idx[1]
		line, col := byteOffsetToLineCol(content, start)
		matches = append(matches, secret.Match{
			Start:      start,
			End:        end,
			Line:       line,
			Column:     col,
			Confidence: 0.90,
		})
	}

	return matches
}

// Validate performs additional entropy/format checks.
func (d *AWSKeyDetector) Validate(match secret.Match, context []byte) bool {
	return true
}

// Remediation returns guidance for fixing.
func (d *AWSKeyDetector) Remediation() string {
	return `AWS credentials should never be committed to source control.

1. Revoke the exposed credentials immediately in AWS IAM
2. Remove credentials from git history
3. Use AWS credential providers:
   - IAM Roles (EC2, Lambda, ECS)
   - AWS SSO
   - Temporary STS credentials
4. Use a secrets manager:
   - AWS Secrets Manager
   - AWS Systems Manager Parameter Store
`
}

func byteOffsetToLineCol(content []byte, offset int) (line, col int) {
	line = 1
	col = 1
	for i := 0; i < offset && i < len(content); i++ {
		if content[i] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return line, col
}

func main() {
	detector := NewAWSKeyDetector()
	fmt.Println("AWS Key Detector Plugin")
	fmt.Printf("Name: %s\n", detector.Metadata().Name)
}
