package main

import (
	"log"
	"log/slog"
	"strings"
)

// newStdLogger adapts net/http's *log.Logger requirement onto a callback, so
// server errors land in the structured logger instead of on stderr.
func newStdLogger(emit func(string)) *log.Logger {
	return log.New(writerFunc(func(p []byte) (int, error) {
		emit(strings.TrimRight(string(p), "\n"))
		return len(p), nil
	}), "", 0)
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// slogErrorLog bridges net/http's *log.Logger requirement into slog at warn
// level, so server errors are structured like everything else.
func slogErrorLog(logger *slog.Logger) *log.Logger {
	return newStdLogger(func(msg string) { logger.Warn("http server", "msg", msg) })
}
