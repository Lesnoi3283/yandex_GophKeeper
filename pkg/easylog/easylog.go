package easylog

import "go.uber.org/zap"

// SecureErrLog logs a message and error if log level is "debug".
// Otherwise - only message will be logged.
func SecureErrLog(message string, err error, logger *zap.SugaredLogger) {
	if logger.Level() == zap.DebugLevel {
		logger.Error(message, zap.Error(err))
	} else {
		logger.Errorf(message)
	}
}
