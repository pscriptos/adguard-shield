package syslog

import (
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
)

type Level int

const (
	Debug Level = iota
	Info
	Warn
	Error
)

type Logger struct {
	mu  sync.Mutex
	min Level
	log *log.Logger
}

func New(w io.Writer, min string) *Logger {
	return &Logger{
		min: ParseLevel(min, Info),
		log: log.New(w, "", log.LstdFlags),
	}
}

func ParseLevel(s string, fallback Level) Level {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "DEBUG":
		return Debug
	case "INFO", "":
		return Info
	case "WARN", "WARNING":
		return Warn
	case "ERROR", "ERR":
		return Error
	default:
		return fallback
	}
}

func LevelName(l Level) string {
	switch l {
	case Debug:
		return "DEBUG"
	case Info:
		return "INFO"
	case Warn:
		return "WARN"
	case Error:
		return "ERROR"
	default:
		return "INFO"
	}
}

func (l *Logger) Enabled(level Level) bool {
	if l == nil {
		return false
	}
	return level >= l.min
}

func (l *Logger) Logf(level Level, format string, args ...any) {
	if !l.Enabled(level) {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.log.Printf("[%s] [ADGUARD-SHIELDD] %s", LevelName(level), fmt.Sprintf(format, args...))
}

func (l *Logger) Debugf(format string, args ...any) { l.Logf(Debug, format, args...) }
func (l *Logger) Infof(format string, args ...any)  { l.Logf(Info, format, args...) }
func (l *Logger) Warnf(format string, args ...any)  { l.Logf(Warn, format, args...) }
func (l *Logger) Errorf(format string, args ...any) { l.Logf(Error, format, args...) }
