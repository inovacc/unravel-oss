//go:build ignore
// +build ignore

package main

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

/* Domain events */
type UserLogin struct {
	Username  string
	IpAddress string
}

type OrderPlaced struct {
	OrderId  int
	Amount   float64
	Currency string
}

type SystemAlert struct {
	Severity string
	Message  string
}

/* Signal - type-safe event emitter */
type Signal[T any] struct {
	mu        sync.RWMutex
	nextId    int64
	callbacks map[int64]func(T)
}

func NewSignal[T any]() *Signal[T] {
	return &Signal[T]{
		callbacks: make(map[int64]func(T)),
	}
}

type Connection struct {
	signal     interface{}
	id         int64
	disconnect func()
}

func (c *Connection) Disconnect() {
	if c.disconnect != nil {
		c.disconnect()
		c.disconnect = nil
	}
}

func (s *Signal[T]) Connect(handler func(T)) *Connection {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.nextId
	s.nextId++
	s.callbacks[id] = handler
	conn := &Connection{
		signal: s,
		id:     id,
	}
	conn.disconnect = func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.callbacks, id)
	}
	return conn
}

func (s *Signal[T]) Emit(arg T) {
	s.mu.RLock()
	handlers := make([]func(T), 0, len(s.callbacks))
	for _, cb := range s.callbacks {
		handlers = append(handlers, cb)
	}
	s.mu.RUnlock()
	for _, handler := range handlers {
		handler(arg)
	}
}

func (s *Signal[T]) SlotCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.callbacks)
}

/* Signal with two parameters */
type Signal2[T1, T2 any] struct {
	mu        sync.RWMutex
	nextId    int64
	callbacks map[int64]func(T1, T2)
}

func NewSignal2[T1, T2 any]() *Signal2[T1, T2] {
	return &Signal2[T1, T2]{
		callbacks: make(map[int64]func(T1, T2)),
	}
}

func (s *Signal2[T1, T2]) Connect(handler func(T1, T2)) *Connection {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := s.nextId
	s.nextId++
	s.callbacks[id] = handler
	conn := &Connection{
		signal: s,
		id:     id,
	}
	conn.disconnect = func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.callbacks, id)
	}
	return conn
}

func (s *Signal2[T1, T2]) Emit(arg1 T1, arg2 T2) {
	s.mu.RLock()
	handlers := make([]func(T1, T2), 0, len(s.callbacks))
	for _, cb := range s.callbacks {
		handlers = append(handlers, cb)
	}
	s.mu.RUnlock()
	for _, handler := range handlers {
		handler(arg1, arg2)
	}
}

func (s *Signal2[T1, T2]) SlotCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.callbacks)
}

/* ScopedConnection - auto-disconnects on scope exit */
type ScopedConnection struct {
	conn *Connection
}

func NewScopedConnection(conn *Connection) *ScopedConnection {
	return &ScopedConnection{conn: conn}
}

func (sc *ScopedConnection) Close() {
	if sc.conn != nil {
		sc.conn.Disconnect()
		sc.conn = nil
	}
}

/* EventBus - type-erased pub/sub */
type EventBus struct {
	mu      sync.RWMutex
	signals map[string]interface{}
}

func NewEventBus() *EventBus {
	return &EventBus{
		signals: make(map[string]interface{}),
	}
}

func getTypeName[T any]() string {
	var zero T
	return fmt.Sprintf("%T", zero)
}

func Subscribe[T any](eb *EventBus, handler func(T)) *Connection {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	typeName := getTypeName[T]()
	sig, exists := eb.signals[typeName]
	if !exists {
		sig = NewSignal[T]()
		eb.signals[typeName] = sig
	}
	return sig.(*Signal[T]).Connect(handler)
}

func Publish[T any](eb *EventBus, event T) {
	eb.mu.RLock()
	typeName := getTypeName[T]()
	sig, exists := eb.signals[typeName]
	eb.mu.RUnlock()
	if exists {
		sig.(*Signal[T]).Emit(event)
	}
}

/* Observable using CRTP pattern (simulated with interface) */
type Observable[T any] struct {
	signal *Signal[T]
}

func NewObservable[T any]() *Observable[T] {
	return &Observable[T]{
		signal: NewSignal[T](),
	}
}

func (o *Observable[T]) OnChange(handler func(T)) *Connection {
	return o.signal.Connect(handler)
}

func (o *Observable[T]) NotifyChange(value T) {
	o.signal.Emit(value)
}

/* AppConfig using Observable pattern */
type AppConfig struct {
	observable     *Observable[*AppConfig]
	debug          bool
	maxConnections int
}

func NewAppConfig() *AppConfig {
	config := &AppConfig{
		debug:          false,
		maxConnections: 100,
	}
	config.observable = NewObservable[*AppConfig]()
	return config
}

func (c *AppConfig) SetDebug(debug bool) {
	c.debug = debug
	c.notifyChange()
}

func (c *AppConfig) SetMaxConnections(max int) {
	c.maxConnections = max
	c.notifyChange()
}

func (c *AppConfig) Debug() bool {
	return c.debug
}

func (c *AppConfig) MaxConnections() int {
	return c.maxConnections
}

func (c *AppConfig) notifyChange() {
	c.observable.NotifyChange(c)
}

func (c *AppConfig) OnChange(handler func(*AppConfig)) *Connection {
	return c.observable.OnChange(handler)
}

func (c *AppConfig) String() string {
	return fmt.Sprintf("Config{debug=%v, max_connections=%d}", c.debug, c.maxConnections)
}

/* EventQueue - async task executor */
type EventQueue struct {
	numWorkers int
	tasks      chan func()
	wg         sync.WaitGroup
	stopOnce   sync.Once
	stopped    atomic.Bool
}

func NewEventQueue(numWorkers int) *EventQueue {
	return &EventQueue{
		numWorkers: numWorkers,
		tasks:      make(chan func(), 100),
	}
}

func (eq *EventQueue) Start() {
	for i := 0; i < eq.numWorkers; i++ {
		eq.wg.Add(1)
		go func() {
			defer eq.wg.Done()
			for task := range eq.tasks {
				task()
			}
		}()
	}
}

func (eq *EventQueue) Post(task func()) {
	if !eq.stopped.Load() {
		eq.tasks <- task
	}
}

func (eq *EventQueue) Stop() {
	eq.stopOnce.Do(func() {
		eq.stopped.Store(true)
		close(eq.tasks)
		eq.wg.Wait()
	})
}

/* Timer - periodic callback executor */
type Timer struct {
	mu      sync.Mutex
	ticker  *time.Ticker
	done    chan struct{}
	OnTick  func()
	running bool
}

func NewTimer() *Timer {
	return &Timer{}
}

func (t *Timer) Start(interval time.Duration, repeat bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.running {
		return
	}
	t.running = true
	t.done = make(chan struct{})
	t.ticker = time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-t.ticker.C:
				if t.OnTick != nil {
					t.OnTick()
				}
				if !repeat {
					t.Stop()
					return
				}
			case <-t.done:
				return
			}
		}
	}()
}

func (t *Timer) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.running {
		return
	}
	t.running = false
	t.ticker.Stop()
	close(t.done)
}

func main() {
	fmt.Println("=== Signal Demo ===")
	{
		onMessage := NewSignal2[int, string]()

		conn1 := onMessage.Connect(func(id int, msg string) {
			fmt.Printf("Handler 1: [%d] %s\n", id, msg)
		})

		conn2 := onMessage.Connect(func(id int, msg string) {
			fmt.Printf("Handler 2: [%d] %s\n", id, msg)
		})

		onMessage.Emit(1, "Hello Signal")
		onMessage.Emit(2, "Operator() syntax")

		fmt.Printf("Connected slots: %d\n", onMessage.SlotCount())
		conn1.Disconnect()
		fmt.Printf("After disconnect: %d\n", onMessage.SlotCount())

		onMessage.Emit(3, "Only handler 2 receives this")
		_ = conn2
	}

	fmt.Println("\n=== Scoped Connection Demo ===")
	{
		onEvent := NewSignal[string]()
		{
			sc := NewScopedConnection(onEvent.Connect(func(s string) {
				fmt.Printf("Scoped handler: %s\n", s)
			}))
			onEvent.Emit("inside scope")
			sc.Close()
		}
		onEvent.Emit("outside scope - no handler")
		fmt.Printf("Slots after scope: %d\n", onEvent.SlotCount())
	}

	fmt.Println("\n=== Event Bus Demo ===")
	{
		bus := NewEventBus()

		loginConn := Subscribe(bus, func(e UserLogin) {
			fmt.Printf("User logged in: %s from %s\n", e.Username, e.IpAddress)
		})

		orderConn := Subscribe(bus, func(e OrderPlaced) {
			fmt.Printf("Order #%d: %.2f %s\n", e.OrderId, e.Amount, e.Currency)
		})

		alertCount := 0
		alertConn := Subscribe(bus, func(e SystemAlert) {
			alertCount++
			fmt.Printf("[%s] %s\n", e.Severity, e.Message)
		})

		Publish(bus, UserLogin{"alice", "192.168.1.1"})
		Publish(bus, UserLogin{"bob", "10.0.0.5"})
		Publish(bus, OrderPlaced{1001, 99.99, "USD"})
		Publish(bus, SystemAlert{"WARN", "High memory usage"})
		Publish(bus, SystemAlert{"ERROR", "Database connection lost"})

		fmt.Printf("Alert count: %d\n", alertCount)

		loginConn.Disconnect()
		Publish(bus, UserLogin{"charlie", "172.16.0.1"})
		_, _, _ = orderConn, alertConn, alertCount
	}

	fmt.Println("\n=== Observable Config (CRTP) ===")
	{
		config := NewAppConfig()

		conn := config.OnChange(func(c *AppConfig) {
			fmt.Printf("Config changed: %s\n", c.String())
		})

		config.SetDebug(true)
		config.SetMaxConnections(200)

		conn.Disconnect()
		config.SetDebug(false)
	}

	fmt.Println("\n=== Async Event Queue ===")
	{
		queue := NewEventQueue(2)
		queue.Start()

		var processed atomic.Int32
		var coutMutex sync.Mutex

		for i := 0; i < 10; i++ {
			i := i
			queue.Post(func() {
				{
					coutMutex.Lock()
					fmt.Fprintf(os.Stdout, "Task %d executed on goroutine\n", i)
					coutMutex.Unlock()
				}
				processed.Add(1)
			})
		}

		for processed.Load() < 10 {
			time.Sleep(10 * time.Millisecond)
		}

		queue.Stop()
		fmt.Printf("Processed: %d tasks\n", processed.Load())
	}

	fmt.Println("\n=== Timer Demo ===")
	{
		timer := NewTimer()
		var ticks atomic.Int32

		timer.OnTick = func() {
			ticks.Add(1)
			fmt.Printf("Tick %d\n", ticks.Load())
		}

		timer.Start(100*time.Millisecond, true)
		time.Sleep(350 * time.Millisecond)
		timer.Stop()

		fmt.Printf("Total ticks: %d\n", ticks.Load())
	}

	fmt.Println("\nAll demos complete.")
}
