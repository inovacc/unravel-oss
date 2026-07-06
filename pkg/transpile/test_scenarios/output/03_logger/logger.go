//go:build ignore
// +build ignore

// Package logging provides a thread-safe logging library inspired by spdlog/glog
package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Level represents the severity level of a log message
type Level int

const (
	Debug Level = iota
	Info
	Warn
	Error
	Fatal
)

// String returns the string representation of a Level
func (l Level) String() string {
	switch l {
	case Debug:
		return "DEBUG"
	case Info:
		return "INFO"
	case Warn:
		return "WARN"
	case Error:
		return "ERROR"
	case Fatal:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// LogRecord represents a single log entry
type LogRecord struct {
	Level      Level
	Message    string
	LoggerName string
	File       string
	Line       int
	Timestamp  time.Time
}

// NewLogRecord creates a new LogRecord
func NewLogRecord(level Level, msg, name, file string, line int) LogRecord {
	return LogRecord{
		Level:      level,
		Message:    msg,
		LoggerName: name,
		File:       file,
		Line:       line,
		Timestamp:  time.Now(),
	}
}

// Formatter is the interface for log formatters
type Formatter interface {
	Format(record LogRecord) string
}

// TextFormatter formats log records as plain text
type TextFormatter struct{}

// Format implements the Formatter interface
func (f *TextFormatter) Format(record LogRecord) string {
	timebuf := record.Timestamp.Format("2006-01-02 15:04:05")

	var sb strings.Builder
	sb.WriteString("[")
	sb.WriteString(timebuf)
	sb.WriteString("] [")
	sb.WriteString(record.Level.String())
	sb.WriteString("] ")

	if record.LoggerName != "" {
		sb.WriteString("[")
		sb.WriteString(record.LoggerName)
		sb.WriteString("] ")
	}

	sb.WriteString(record.Message)

	if record.File != "" {
		sb.WriteString(" (")
		sb.WriteString(record.File)
		sb.WriteString(":")
		sb.WriteString(strconv.Itoa(record.Line))
		sb.WriteString(")")
	}

	return sb.String()
}

// JsonFormatter formats log records as JSON
type JsonFormatter struct{}

// Format implements the Formatter interface
func (f *JsonFormatter) Format(record LogRecord) string {
	timebuf := record.Timestamp.Format("2006-01-02T15:04:05")

	var sb strings.Builder
	sb.WriteString(`{"time":"`)
	sb.WriteString(timebuf)
	sb.WriteString(`","level":"`)
	sb.WriteString(record.Level.String())
	sb.WriteString(`","msg":"`)
	sb.WriteString(escapeJSON(record.Message))
	sb.WriteString(`"`)

	if record.LoggerName != "" {
		sb.WriteString(`,"logger":"`)
		sb.WriteString(record.LoggerName)
		sb.WriteString(`"`)
	}

	if record.File != "" {
		sb.WriteString(`,"file":"`)
		sb.WriteString(record.File)
		sb.WriteString(`","line":`)
		sb.WriteString(strconv.Itoa(record.Line))
	}

	sb.WriteString("}")
	return sb.String()
}

func escapeJSON(s string) string {
	var sb strings.Builder
	sb.Grow(len(s))
	for _, c := range s {
		switch c {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\n':
			sb.WriteString(`\n`)
		case '\t':
			sb.WriteString(`\t`)
		default:
			sb.WriteRune(c)
		}
	}
	return sb.String()
}

// Sink is the interface for log output destinations
type Sink interface {
	Write(formattedMsg string)
	Flush()
	SetLevel(level Level)
	Level() Level
	ShouldLog(level Level) bool
}

// BaseSink provides common functionality for sinks
type BaseSink struct {
	minLevel Level
}

// SetLevel sets the minimum log level for this sink
func (s *BaseSink) SetLevel(level Level) {
	s.minLevel = level
}

// Level returns the minimum log level for this sink
func (s *BaseSink) Level() Level {
	return s.minLevel
}

// ShouldLog returns true if the given level should be logged
func (s *BaseSink) ShouldLog(level Level) bool {
	return level >= s.minLevel
}

// ConsoleSink writes log messages to stdout or stderr
type ConsoleSink struct {
	BaseSink
	stream *os.File
	mutex  sync.Mutex
}

// NewConsoleSink creates a new ConsoleSink
func NewConsoleSink(useStderr bool) *ConsoleSink {
	stream := os.Stdout
	if useStderr {
		stream = os.Stderr
	}
	return &ConsoleSink{
		BaseSink: BaseSink{minLevel: Debug},
		stream:   stream,
	}
}

// Write implements the Sink interface
func (s *ConsoleSink) Write(msg string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	fmt.Fprintln(s.stream, msg)
}

// Flush implements the Sink interface
func (s *ConsoleSink) Flush() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.stream.Sync()
}

// FileSink writes log messages to a file with rotation support
type FileSink struct {
	BaseSink
	filename    string
	file        *os.File
	mutex       sync.Mutex
	maxSize     uint
	maxFiles    int
	currentSize uint
}

// NewFileSink creates a new FileSink with rotation
func NewFileSink(filename string, maxSize uint, maxFiles int) (*FileSink, error) {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("cannot open log file: %s: %w", filename, err)
	}

	info, err := file.Stat()
	currentSize := uint(0)
	if err == nil {
		currentSize = uint(info.Size())
	}

	return &FileSink{
		BaseSink:    BaseSink{minLevel: Debug},
		filename:    filename,
		file:        file,
		maxSize:     maxSize,
		maxFiles:    maxFiles,
		currentSize: currentSize,
	}, nil
}

// Close closes the file sink
func (s *FileSink) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}

// Write implements the Sink interface
func (s *FileSink) Write(msg string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	msgSize := uint(len(msg) + 1)
	if s.currentSize+msgSize > s.maxSize {
		s.rotate()
	}

	fmt.Fprintln(s.file, msg)
	s.currentSize += msgSize
}

// Flush implements the Sink interface
func (s *FileSink) Flush() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.file != nil {
		s.file.Sync()
	}
}

func (s *FileSink) rotate() {
	if s.file != nil {
		s.file.Close()
	}

	for i := s.maxFiles - 1; i > 0; i-- {
		src := s.filename + "." + strconv.Itoa(i)
		dst := s.filename + "." + strconv.Itoa(i+1)
		os.Rename(src, dst)
	}

	os.Rename(s.filename, s.filename+".1")
	file, err := os.OpenFile(s.filename, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		s.file = file
		s.currentSize = 0
	}
}

// CallbackSink calls a custom callback function for each log message
type CallbackSink struct {
	BaseSink
	callback func(Level, string)
}

// NewCallbackSink creates a new CallbackSink
func NewCallbackSink(callback func(Level, string)) *CallbackSink {
	return &CallbackSink{
		BaseSink: BaseSink{minLevel: Debug},
		callback: callback,
	}
}

// Write implements the Sink interface
func (s *CallbackSink) Write(msg string) {
	if s.callback != nil {
		s.callback(Info, msg)
	}
}

// Flush implements the Sink interface
func (s *CallbackSink) Flush() {}

// Logger is the main logging class
type Logger struct {
	name      string
	level     Level
	formatter Formatter
	sinks     []Sink
	mutex     sync.Mutex
}

// NewLogger creates a new Logger
func NewLogger(name string) *Logger {
	return &Logger{
		name:      name,
		level:     Debug,
		formatter: &TextFormatter{},
		sinks:     make([]Sink, 0),
	}
}

// AddSink adds a sink to the logger
func (l *Logger) AddSink(sink Sink) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.sinks = append(l.sinks, sink)
}

// SetLevel sets the minimum log level
func (l *Logger) SetLevel(level Level) {
	l.level = level
}

// Level returns the minimum log level
func (l *Logger) Level() Level {
	return l.level
}

// SetFormatter sets the log formatter
func (l *Logger) SetFormatter(formatter Formatter) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.formatter = formatter
}

// Log logs a message at the specified level
func (l *Logger) Log(level Level, msg, file string, line int) {
	if level < l.level {
		return
	}

	record := NewLogRecord(level, msg, l.name, file, line)

	var formatted string
	l.mutex.Lock()
	formatted = l.formatter.Format(record)
	sinks := l.sinks
	l.mutex.Unlock()

	for _, sink := range sinks {
		if sink.ShouldLog(level) {
			sink.Write(formatted)
		}
	}

	if level == Fatal {
		l.Flush()
		os.Exit(1)
	}
}

// Debug logs a debug message
func (l *Logger) Debug(msg string) {
	l.Log(Debug, msg, "", 0)
}

// Info logs an info message
func (l *Logger) Info(msg string) {
	l.Log(Info, msg, "", 0)
}

// Warn logs a warning message
func (l *Logger) Warn(msg string) {
	l.Log(Warn, msg, "", 0)
}

// Error logs an error message
func (l *Logger) Error(msg string) {
	l.Log(Error, msg, "", 0)
}

// Flush flushes all sinks
func (l *Logger) Flush() {
	l.mutex.Lock()
	sinks := l.sinks
	l.mutex.Unlock()

	for _, sink := range sinks {
		sink.Flush()
	}
}

// Name returns the logger name
func (l *Logger) Name() string {
	return l.name
}

// Registry manages a collection of loggers (singleton)
type Registry struct {
	loggers      map[string]*Logger
	mutex        sync.Mutex
	defaultLevel Level
}

var (
	registryInstance *Registry
	registryOnce     sync.Once
)

// GetRegistry returns the singleton Registry instance
func GetRegistry() *Registry {
	registryOnce.Do(func() {
		registryInstance = &Registry{
			loggers:      make(map[string]*Logger),
			defaultLevel: Info,
		}
	})
	return registryInstance
}

// Get returns a logger with the given name, creating it if necessary
func (r *Registry) Get(name string) *Logger {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if logger, ok := r.loggers[name]; ok {
		return logger
	}

	logger := NewLogger(name)
	r.loggers[name] = logger
	return logger
}

// SetDefaultLevel sets the default log level for new loggers
func (r *Registry) SetDefaultLevel(level Level) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.defaultLevel = level
}

// Drop removes a logger from the registry
func (r *Registry) Drop(name string) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	delete(r.loggers, name)
}

// DropAll removes all loggers from the registry
func (r *Registry) DropAll() {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.loggers = make(map[string]*Logger)
}

// Helper functions for convenience logging with file/line information

// LogDebug logs a debug message with file and line information
func LogDebug(logger *Logger, msg, file string, line int) {
	logger.Log(Debug, msg, filepath.Base(file), line)
}

// LogInfo logs an info message with file and line information
func LogInfo(logger *Logger, msg, file string, line int) {
	logger.Log(Info, msg, filepath.Base(file), line)
}

// LogWarn logs a warning message with file and line information
func LogWarn(logger *Logger, msg, file string, line int) {
	logger.Log(Warn, msg, filepath.Base(file), line)
}

// LogError logs an error message with file and line information
func LogError(logger *Logger, msg, file string, line int) {
	logger.Log(Error, msg, filepath.Base(file), line)
}
