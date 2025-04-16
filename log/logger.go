package log

type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

type EmptyLogger struct{}

func (l *EmptyLogger) Debug(_ string, _ ...any) {}
func (l *EmptyLogger) Info(_ string, _ ...any)  {}
func (l *EmptyLogger) Warn(_ string, _ ...any)  {}
func (l *EmptyLogger) Error(_ string, _ ...any) {}
