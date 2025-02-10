package logger

import (
	"log/slog"
	"os"
)

// Create a new logger
var Logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
	Level: slog.LevelError,
}))
