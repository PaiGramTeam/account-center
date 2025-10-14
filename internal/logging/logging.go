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
