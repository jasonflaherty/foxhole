# AWS Key Detector Plugin

Example SecretRule plugin detecting hardcoded AWS credentials.

## Features

- Detects AWS Access Key IDs (AKIA + 16 chars)
- Detects AWS Secret Access Keys
- High-confidence pattern matching
- Detailed remediation guidance

## Usage

```yaml
secret_rules:
  - name: aws-keys
    plugin: "github.com/foxhole-plugins/secret-aws"
    enabled: true
```
