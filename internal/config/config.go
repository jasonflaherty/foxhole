package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"
)

const (
	// MaxDBAge is the maximum age of vulnerability data before refresh is recommended.
	MaxDBAge = 30 * 24 * time.Hour

	envPrefix = "FOXHOLE"
)

// Config holds runtime configuration for Foxhole.
type Config struct {
	DBPath       string `mapstructure:"db_path"`
	Offline      bool   `mapstructure:"offline"`
	LogLevel     string `mapstructure:"log_level"`
	ArchiveDir   string `mapstructure:"archive_dir"`
	Report       string `mapstructure:"report"`
	NVDAPIKey    string `mapstructure:"nvd_api_key"`
	Secrets      bool   `mapstructure:"secrets"`
	EOL          bool   `mapstructure:"eol"`
	Misconfig    bool   `mapstructure:"misconfig"`
	Licenses     bool   `mapstructure:"licenses"`
	Enrich       bool   `mapstructure:"enrich"`
	FailOn       string `mapstructure:"fail_on"`
	PolicyPath   string `mapstructure:"policy"`
	PolicyDir    string `mapstructure:"policy_dir"`
	Remediate    bool   `mapstructure:"remediate"`
	RemediateAI  bool   `mapstructure:"remediate_ai"`
	SplitReports bool   `mapstructure:"split_reports"`
	MaxDBAge     string `mapstructure:"max_db_age"` // Go duration, e.g. 720h; empty disables
	APIToken     string `mapstructure:"api_token"`
	Evidence     bool   `mapstructure:"evidence"`
	EvidenceDir  string `mapstructure:"evidence_dir"`
	Triage       bool   `mapstructure:"triage"`
	TriageAI     bool   `mapstructure:"triage_ai"`
}

// DefaultDBPath returns the default SQLite database path.
func DefaultDBPath() string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".foxhole", "foxhole.db")
	}
	return filepath.Join(".", "foxhole.db")
}

// Load reads configuration from foxhole.yaml, environment variables, and applies defaults.
// CLI flags should be bound to viper before calling Load.
func Load() (*Config, error) {
	v := viper.New()
	v.SetConfigName("foxhole")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("$HOME/.foxhole")
	v.AddConfigPath("/etc/foxhole")

	v.SetEnvPrefix(envPrefix)
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	v.AutomaticEnv()

	v.SetDefault("db_path", DefaultDBPath())
	v.SetDefault("offline", false)
	v.SetDefault("log_level", "info")
	v.SetDefault("archive_dir", "archive")
	v.SetDefault("report", "console")
	v.SetDefault("nvd_api_key", "")
	v.SetDefault("secrets", true)
	v.SetDefault("eol", true)
	v.SetDefault("misconfig", true)
	v.SetDefault("licenses", true)
	v.SetDefault("enrich", true)
	v.SetDefault("fail_on", "")
	v.SetDefault("policy", "")
	v.SetDefault("remediate", false)
	v.SetDefault("remediate_ai", false)
	v.SetDefault("split_reports", false)
	v.SetDefault("max_db_age", "")
	v.SetDefault("policy_dir", "")
	v.SetDefault("api_token", "")
	v.SetDefault("evidence", false)
	v.SetDefault("evidence_dir", "foxhole-evidence")
	v.SetDefault("triage", false)
	v.SetDefault("triage_ai", false)

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("read config: %w", err)
		}
	}

	cfg := &Config{}
	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	return cfg, nil
}

// BindViper exposes a shared viper instance for CLI flag binding.
func NewViper() *viper.Viper {
	v := viper.New()
	v.SetConfigName("foxhole")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("$HOME/.foxhole")
	v.AddConfigPath("/etc/foxhole")
	v.SetEnvPrefix(envPrefix)
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	v.AutomaticEnv()
	v.SetDefault("db_path", DefaultDBPath())
	v.SetDefault("offline", false)
	v.SetDefault("log_level", "info")
	v.SetDefault("archive_dir", "archive")
	v.SetDefault("report", "console")
	v.SetDefault("nvd_api_key", "")
	v.SetDefault("secrets", true)
	v.SetDefault("eol", true)
	v.SetDefault("misconfig", true)
	v.SetDefault("licenses", true)
	v.SetDefault("enrich", true)
	v.SetDefault("fail_on", "")
	v.SetDefault("policy", "")
	v.SetDefault("remediate", false)
	v.SetDefault("remediate_ai", false)
	v.SetDefault("split_reports", false)
	v.SetDefault("max_db_age", "")
	v.SetDefault("policy_dir", "")
	v.SetDefault("api_token", "")
	v.SetDefault("evidence", false)
	v.SetDefault("evidence_dir", "foxhole-evidence")
	v.SetDefault("triage", false)
	v.SetDefault("triage_ai", false)
	return v
}

// FromViper unmarshals config from an already-populated viper instance.
func FromViper(v *viper.Viper) (*Config, error) {
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("read config: %w", err)
		}
	}
	cfg := &Config{}
	if err := v.Unmarshal(cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	return cfg, nil
}
