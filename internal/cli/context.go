package cli

import (
	"context"

	"github.com/jasonflaherty/foxhole/internal/config"
	"github.com/spf13/viper"
)

type ctxKey int

const (
	cfgKey ctxKey = iota
	viperKey
)

func withConfig(ctx context.Context, cfg *config.Config, v *viper.Viper) context.Context {
	ctx = context.WithValue(ctx, cfgKey, cfg)
	ctx = context.WithValue(ctx, viperKey, v)
	return ctx
}

func configFrom(cmd interface{ Context() context.Context }) *config.Config {
	if cfg, ok := cmd.Context().Value(cfgKey).(*config.Config); ok && cfg != nil {
		return cfg
	}
	return &config.Config{DBPath: config.DefaultDBPath(), LogLevel: "info"}
}
