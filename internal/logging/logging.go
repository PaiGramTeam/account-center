package logging

import (
	"sync"

	"go.uber.org/zap"
	"gorm.io/gorm/logger"
)

var (
	zapOnce   sync.Once
	zapLogger *zap.Logger
	zapErr    error
)

// NewZapWriter returns a gorm logger writer backed by zap.
func NewZapWriter(name string) (logger.Writer, error) {
	log, err := getZapLogger()
	if err != nil {
		return nil, err
	}
	return &zapWriter{sugar: log.Named(name).Sugar()}, nil
}

// Sync flushes buffered zap logs; safe to call multiple times.
func Sync() {
	if zapLogger != nil {
		_ = zapLogger.Sync()
	}
}

func getZapLogger() (*zap.Logger, error) {
	zapOnce.Do(func() {
		zapLogger, zapErr = zap.NewProduction()
	})
	return zapLogger, zapErr
}

type zapWriter struct {
	sugar *zap.SugaredLogger
}

func (w *zapWriter) Printf(format string, args ...interface{}) {
	w.sugar.Infof(format, args...)
}

// Info logs an info level message
func Info(msg string, fields ...zap.Field) {
	log, err := getZapLogger()
	if err != nil {
		return
	}
	log.Info(msg, fields...)
}

// Error logs an error level message
func Error(msg string, fields ...zap.Field) {
	log, err := getZapLogger()
	if err != nil {
		return
	}
	log.Error(msg, fields...)
}

// Debug logs a debug level message
func Debug(msg string, fields ...zap.Field) {
	log, err := getZapLogger()
	if err != nil {
		return
	}
	log.Debug(msg, fields...)
}

// Warn logs a warning level message
func Warn(msg string, fields ...zap.Field) {
	log, err := getZapLogger()
	if err != nil {
		return
	}
	log.Warn(msg, fields...)
}
