# npm Scanner Plugin

Example Scanner plugin for discovering Node.js npm packages.

## Features

- Discovers npm packages from package.json files
- Recursively walks project directory
- Separates dependencies and devDependencies
- Configurable directory exclusions

## Usage

```yaml
scanners:
  - name: npm
    plugin: "github.com/foxhole-plugins/scanner-npm"
    enabled: true
```
