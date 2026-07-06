//go:build ignore
// +build ignore

package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

// Level represents logging severity
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// Sink interface for log destinations
type Sink interface {
	Write(msg string)
	Flush()
	SetLevel(level Level)
}

// Formatter interface for log formatting
type Formatter interface {
	Format(level Level, name string, msg string) string
}

// DefaultFormatter provides simple text formatting
type DefaultFormatter struct{}

func (f *DefaultFormatter) Format(level Level, name string, msg string) string {
	return fmt.Sprintf("[%s] %s: %s", level, name, msg)
}

// JsonFormatter provides JSON formatting
type JsonFormatter struct{}

func (f *JsonFormatter) Format(level Level, name string, msg string) string {
	return fmt.Sprintf(`{"level":"%s","logger":"%s","message":"%s"}`, level, name, msg)
}

// ConsoleSink writes to stdout or stderr
type ConsoleSink struct {
	mu     sync.Mutex
	stderr bool
	level  Level
}

func NewConsoleSink(stderr ...bool) *ConsoleSink {
	useStderr := false
	if len(stderr) > 0 {
		useStderr = stderr[0]
	}
	return &ConsoleSink{
		stderr: useStderr,
		level:  LevelDebug,
	}
}

func (s *ConsoleSink) SetLevel(level Level) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.level = level
}

func (s *ConsoleSink) Write(msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stderr {
		fmt.Fprintln(os.Stderr, msg)
	} else {
		fmt.Println(msg)
	}
}

func (s *ConsoleSink) Flush() {
	// No buffering for console output
}

// CallbackSink calls a function for each log message
type CallbackSink struct {
	mu       sync.Mutex
	callback func(Level, string)
	level    Level
}

func NewCallbackSink(callback func(Level, string)) *CallbackSink {
	return &CallbackSink{
		callback: callback,
		level:    LevelDebug,
	}
}

func (s *CallbackSink) SetLevel(level Level) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.level = level
}

func (s *CallbackSink) Write(msg string) {
	s.mu.Lock()
	callback := s.callback
	s.mu.Unlock()
	if callback != nil {
		// Extract level from message if possible, otherwise use Info
		callback(LevelInfo, msg)
	}
}

func (s *CallbackSink) Flush() {
	// No buffering
}

// Logger is the main logging component
type Logger struct {
	mu        sync.Mutex
	name      string
	level     Level
	sinks     []Sink
	formatter Formatter
}

func NewLogger(name string) *Logger {
	return &Logger{
		name:      name,
		level:     LevelInfo,
		sinks:     make([]Sink, 0),
		formatter: &DefaultFormatter{},
	}
}

func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

func (l *Logger) SetFormatter(formatter Formatter) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.formatter = formatter
}

func (l *Logger) AddSink(sink Sink) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sinks = append(l.sinks, sink)
}

func (l *Logger) log(level Level, msg string) {
	l.mu.Lock()
	if level < l.level {
		l.mu.Unlock()
		return
	}
	formatter := l.formatter
	name := l.name
	sinks := l.sinks
	l.mu.Unlock()

	formatted := formatter.Format(level, name, msg)
	for _, sink := range sinks {
		sink.Write(formatted)
	}
}

func (l *Logger) Debug(msg string) {
	l.log(LevelDebug, msg)
}

func (l *Logger) Info(msg string) {
	l.log(LevelInfo, msg)
}

func (l *Logger) Warn(msg string) {
	l.log(LevelWarn, msg)
}

func (l *Logger) Error(msg string) {
	l.log(LevelError, msg)
}

func (l *Logger) Flush() {
	l.mu.Lock()
	sinks := l.sinks
	l.mu.Unlock()

	for _, sink := range sinks {
		sink.Flush()
	}
}

// Registry maintains a collection of loggers
type Registry struct {
	mu      sync.Mutex
	loggers map[string]*Logger
}

var (
	registryInstance *Registry
	registryOnce     sync.Once
)

func GetRegistry() *Registry {
	registryOnce.Do(func() {
		registryInstance = &Registry{
			loggers: make(map[string]*Logger),
		}
	})
	return registryInstance
}

func (r *Registry) Get(name string) *Logger {
	r.mu.Lock()
	defer r.mu.Unlock()

	if logger, exists := r.loggers[name]; exists {
		return logger
	}

	logger := NewLogger(name)
	r.loggers[name] = logger
	return logger
}

// FilterSink only passes messages containing a keyword
type FilterSink struct {
	mu      sync.Mutex
	inner   Sink
	keyword string
	level   Level
}

func NewFilterSink(inner Sink, keyword string) *FilterSink {
	return &FilterSink{
		inner:   inner,
		keyword: keyword,
		level:   LevelDebug,
	}
}

func (s *FilterSink) SetLevel(level Level) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.level = level
}

func (s *FilterSink) Write(msg string) {
	s.mu.Lock()
	keyword := s.keyword
	inner := s.inner
	s.mu.Unlock()

	if strings.Contains(msg, keyword) {
		inner.Write(msg)
	}
}

func (s *FilterSink) Flush() {
	s.mu.Lock()
	inner := s.inner
	s.mu.Unlock()
	inner.Flush()
}

// worker demonstrates multi-threaded logging
func worker(logger *Logger, id int, count int, wg *sync.WaitGroup) {
	defer wg.Done()
	for i := 0; i < count; i++ {
		msg := fmt.Sprintf("Worker %d iteration %d", id, i)
		logger.Info(msg)
	}
}

func main() {
	// Create logger with console + file sinks
	logger := NewLogger("app")

	console := NewConsoleSink()
	console.SetLevel(LevelInfo)
	logger.AddSink(console)

	// Error-only console sink on stderr
	errConsole := NewConsoleSink(true)
	errConsole.SetLevel(LevelError)
	logger.AddSink(errConsole)

	// Callback sink: count messages
	var msgCount int64
	counter := NewCallbackSink(func(level Level, msg string) {
		atomic.AddInt64(&msgCount, 1)
	})
	logger.AddSink(counter)

	// Basic logging
	logger.SetLevel(LevelDebug)
	logger.Debug("Application starting")
	logger.Info("Configuration loaded")
	logger.Warn("Deprecated API in use")
	logger.Error("Connection timeout after 30s")

	// Use info logging with context
	logger.Info("Starting worker threads")

	// Multi-threaded logging
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go worker(logger, i, 5, &wg)
	}

	wg.Wait()

	logger.Info("All workers complete")

	// JSON formatter demo
	jsonLogger := NewLogger("json")
	jsonLogger.SetFormatter(&JsonFormatter{})
	jsonLogger.AddSink(NewConsoleSink())

	jsonLogger.Info("Structured log message")
	jsonLogger.Warn("Something might be wrong")

	// Registry demo
	registry := GetRegistry()
	dbLogger := registry.Get("database")
	dbLogger.AddSink(console)
	dbLogger.Info("Connected to PostgreSQL")
	dbLogger.Info("Query executed in 15ms")

	// Filter sink demo
	filtered := NewFilterSink(console, "ERROR")
	filterLogger := NewLogger("filtered")
	filterLogger.AddSink(filtered)
	filterLogger.Info("This will be filtered out")
	filterLogger.Error("ERROR: this passes the filter")

	logger.Flush()
	fmt.Printf("\nTotal messages logged: %d\n", atomic.LoadInt64(&msgCount))
}
