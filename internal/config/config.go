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
	DBPath     string `mapstructure:"db_path"`
	Offline    bool   `mapstructure:"offline"`
	LogLevel   string `mapstructure:"log_level"`
	ArchiveDir string `mapstructure:"archive_dir"`
	Report     string `mapstructure:"report"`
	NVDAPIKey  string `mapstructure:"nvd_api_key"`
	Secrets    bool   `mapstructure:"secrets"`
	EOL        bool   `mapstructure:"eol"`
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
