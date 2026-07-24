package policy

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadFile reads a policy YAML file.
func LoadFile(path string) (Policy, error) {
	if path == "" {
		return Policy{}, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("read policy: %w", err)
	}
	var p Policy
	if err := yaml.Unmarshal(b, &p); err != nil {
		return Policy{}, fmt.Errorf("parse policy: %w", err)
	}
	return p, nil
}
