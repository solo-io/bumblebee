package logger

import (
	"context"
	"io"
	"log"
	"os"
)

type LoggerKey struct{}

type Logger interface {
	Print(text string)
}

type stdLogger struct {
	logger *log.Logger
}

func newStdLogger(logger *log.Logger) stdLogger {
	return stdLogger{
		logger,
	}
}

func (s stdLogger) Print(text string) {
	s.logger.Print(text)
}

func CreateContextWithLogger(ctx context.Context, debug bool) (context.Context, func()) {
	var logger Logger
	var cleanupFunc func()
	if debug {
		f, err := os.OpenFile("debug.log", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
		if err != nil {
			log.Fatalf("error opening file: %v", err)
		}
		cleanupFunc = func() { f.Close() }
		logger = newStdLogger(log.New(f, "", log.LstdFlags))
	} else {
		cleanupFunc = func() {}
		logger = newStdLogger(log.New(io.Discard, "", 0))
	}
	return context.WithValue(ctx, LoggerKey{}, logger), cleanupFunc
}
