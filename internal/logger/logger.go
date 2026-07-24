package logger

import (
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	mu     sync.RWMutex
	global *zap.Logger
)

// Init configures the global zap logger.
func Init(level string, development bool) error {
	cfg := zap.NewProductionConfig()
	if development {
		cfg = zap.NewDevelopmentConfig()
	}

	var zapLevel zapcore.Level
	if err := zapLevel.UnmarshalText([]byte(level)); err != nil {
		zapLevel = zapcore.InfoLevel
	}
	cfg.Level = zap.NewAtomicLevelAt(zapLevel)

	log, err := cfg.Build()
	if err != nil {
		return err
	}

	mu.Lock()
	if global != nil {
		_ = global.Sync()
	}
	global = log
	mu.Unlock()
	return nil
}

// L returns the global logger, initializing a no-op logger if needed.
func L() *zap.Logger {
	mu.RLock()
	log := global
	mu.RUnlock()
	if log != nil {
		return log
	}
	mu.Lock()
	defer mu.Unlock()
	if global == nil {
		global = zap.NewNop()
	}
	return global
}

// Sync flushes buffered log entries.
func Sync() {
	mu.RLock()
	log := global
	mu.RUnlock()
	if log != nil {
		_ = log.Sync()
	}
}
