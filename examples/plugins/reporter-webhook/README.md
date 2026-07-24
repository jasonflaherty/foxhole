# Webhook Reporter Plugin

Example Reporter plugin for sending scan findings to HTTP webhooks.

## Features

- Sends findings to HTTP webhooks
- Supports Slack, Discord, custom APIs
- Summary statistics by severity
- Bearer token authentication

## Usage

```yaml
reporters:
  - name: slack
    plugin: "github.com/foxhole-plugins/reporter-webhook"
    enabled: true
    config:
      endpoint: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
```
