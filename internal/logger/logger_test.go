package logger_test

import (
	"testing"

	"github.com/jasonflaherty/foxhole/internal/logger"
)

func TestInitAndL(t *testing.T) {
	if err := logger.Init("debug", true); err != nil {
		t.Fatal(err)
	}
	if logger.L() == nil {
		t.Fatal("nil logger")
	}
	logger.L().Debug("hello")
	logger.Sync()

	if err := logger.Init("not-a-level", false); err != nil {
		t.Fatal(err)
	}
	logger.L().Info("fallback level")
}
