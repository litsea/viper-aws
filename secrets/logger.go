package secrets

type Logger interface {
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

type emptyLogger struct{}

func (l *emptyLogger) Warn(msg string, args ...any) {}

func (l *emptyLogger) Error(msg string, args ...any) {}
