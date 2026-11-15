// Package logx sets up logging the same way in every program: log/slog, text lines on standard error,
// with a "component" attribute. Nothing in the code base uses the standard "log" package.
package logx

import (
	"io"
	"log/slog"
	"os"
)

// Setup makes the default logger write text lines to standard error, each carrying the component name,
// and returns it. The ZTX_LOG_LEVEL variable (debug, info, warn, error) sets the level; the default is info.
func Setup(component string) *slog.Logger { return SetupTo(os.Stderr, component) }

// SetupTo is Setup with another destination.
func SetupTo(w io.Writer, component string) *slog.Logger {
	var lvl slog.LevelVar
	_ = lvl.UnmarshalText([]byte(os.Getenv("ZTX_LOG_LEVEL"))) // empty or unknown leaves info
	l := slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: &lvl})).With("component", component)
	slog.SetDefault(l)
	return l
}

// Fatal logs at error level and exits with status 1.
func Fatal(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}

// Die logs the error as the message and exits with status 1.
func Die(err error) { Fatal(err.Error()) }
