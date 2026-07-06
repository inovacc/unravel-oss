//go:build ignore
// +build ignore

package event

import (
	"reflect"
	"sync"
	"sync/atomic"
	"time"
)

// ConnectionId is a unique connection identifier
type ConnectionId uint64

// EventBase is the interface for all events
type EventBase interface {
	Type() reflect.Type
	Name() string
}

// Event is a typed event with payload
type Event[T any] struct {
	Data T
}

func NewEvent[T any](data T) *Event[T] {
	return &Event[T]{Data: data}
}

func (e *Event[T]) Type() reflect.Type {
	var zero T
	return reflect.TypeOf(zero)
}

func (e *Event[T]) Name() string {
	var zero T
	return reflect.TypeOf(zero).String()
}

// Connection is a handle that can disconnect a callback
type Connection struct {
	id           ConnectionId
	disconnectFn func()
}

func NewConnection(id ConnectionId, disconnect func()) Connection {
	return Connection{
		id:           id,
		disconnectFn: disconnect,
	}
}

func (c *Connection) Disconnect() {
	if c.disconnectFn != nil {
		c.disconnectFn()
		c.disconnectFn = nil
	}
}

func (c *Connection) Id() ConnectionId {
	return c.id
}

func (c *Connection) Connected() bool {
	return c.disconnectFn != nil
}

// ScopedConnection auto-disconnects on destruction (use with defer)
type ScopedConnection struct {
	conn Connection
}

func NewScopedConnection(conn Connection) *ScopedConnection {
	return &ScopedConnection{conn: conn}
}

func (sc *ScopedConnection) Close() {
	sc.conn.Disconnect()
}

func (sc *ScopedConnection) Get() *Connection {
	return &sc.conn
}

// Signal is a type-safe event emitter with multiple subscribers
type Signal[Args any] struct {
	slots  map[ConnectionId]func(Args)
	nextId ConnectionId
	mutex  sync.Mutex
}

func NewSignal[Args any]() *Signal[Args] {
	return &Signal[Args]{
		slots:  make(map[ConnectionId]func(Args)),
		nextId: 1,
	}
}

// Connect adds a callback and returns a connection handle
func (s *Signal[Args]) Connect(slot func(Args)) Connection {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	id := s.nextId
	s.nextId++
	s.slots[id] = slot

	return NewConnection(id, func() {
		s.mutex.Lock()
		defer s.mutex.Unlock()
		delete(s.slots, id)
	})
}

// Emit calls all connected slots
func (s *Signal[Args]) Emit(args Args) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	for _, slot := range s.slots {
		slot(args)
	}
}

// Call is an alias for Emit (simulating operator())
func (s *Signal[Args]) Call(args Args) {
	s.Emit(args)
}

func (s *Signal[Args]) SlotCount() int {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return len(s.slots)
}

// EventBus is a central pub/sub with type-erased handlers
type EventBus struct {
	handlers map[reflect.Type][]handlerEntry
	nextId   ConnectionId
	mutex    sync.Mutex
}

type handlerEntry struct {
	id      ConnectionId
	handler func(interface{})
}

func NewEventBus() *EventBus {
	return &EventBus{
		handlers: make(map[reflect.Type][]handlerEntry),
		nextId:   1,
	}
}

// Subscribe registers a typed event handler
func Subscribe[T any](bus *EventBus, handler func(T)) Connection {
	bus.mutex.Lock()
	defer bus.mutex.Unlock()

	var zero T
	eventType := reflect.TypeOf(zero)
	id := bus.nextId
	bus.nextId++

	entry := handlerEntry{
		id: id,
		handler: func(event interface{}) {
			if typed, ok := event.(T); ok {
				handler(typed)
			}
		},
	}

	bus.handlers[eventType] = append(bus.handlers[eventType], entry)

	return NewConnection(id, func() {
		bus.mutex.Lock()
		defer bus.mutex.Unlock()

		entries := bus.handlers[eventType]
		filtered := make([]handlerEntry, 0, len(entries))
		for _, e := range entries {
			if e.id != id {
				filtered = append(filtered, e)
			}
		}
		bus.handlers[eventType] = filtered
	})
}

// Publish sends an event to all subscribers
func Publish[T any](bus *EventBus, event T) {
	bus.mutex.Lock()
	defer bus.mutex.Unlock()

	eventType := reflect.TypeOf(event)
	entries, ok := bus.handlers[eventType]
	if !ok {
		return
	}

	for _, entry := range entries {
		entry.handler(event)
	}
}

// EventQueue is an async event queue with worker threads
type EventQueue struct {
	tasks      []func()
	workers    []*sync.WaitGroup
	mutex      sync.Mutex
	cond       *sync.Cond
	running    atomic.Bool
	numWorkers int
	stopCh     chan struct{}
}

func NewEventQueue(numWorkers int) *EventQueue {
	eq := &EventQueue{
		tasks:      make([]func(), 0),
		numWorkers: numWorkers,
		stopCh:     make(chan struct{}),
	}
	eq.cond = sync.NewCond(&eq.mutex)
	return eq
}

func (eq *EventQueue) Start() {
	eq.running.Store(true)

	for i := 0; i < eq.numWorkers; i++ {
		go eq.workerLoop()
	}
}

func (eq *EventQueue) Stop() {
	eq.mutex.Lock()
	eq.running.Store(false)
	eq.mutex.Unlock()

	eq.cond.Broadcast()
	close(eq.stopCh)
}

func (eq *EventQueue) Post(task func()) {
	eq.mutex.Lock()
	eq.tasks = append(eq.tasks, task)
	eq.mutex.Unlock()

	eq.cond.Signal()
}

// PostDelayed posts a task with delay
func (eq *EventQueue) PostDelayed(task func(), delay time.Duration) {
	eq.Post(func() {
		time.Sleep(delay)
		task()
	})
}

func (eq *EventQueue) Pending() int {
	eq.mutex.Lock()
	defer eq.mutex.Unlock()
	return len(eq.tasks)
}

func (eq *EventQueue) workerLoop() {
	for {
		eq.mutex.Lock()
		for eq.running.Load() && len(eq.tasks) == 0 {
			eq.cond.Wait()
		}

		if !eq.running.Load() && len(eq.tasks) == 0 {
			eq.mutex.Unlock()
			return
		}

		if len(eq.tasks) == 0 {
			eq.mutex.Unlock()
			continue
		}

		task := eq.tasks[0]
		eq.tasks = eq.tasks[1:]
		eq.mutex.Unlock()

		task()
	}
}

// Observable is a mixin interface for observable types
type Observable[T any] interface {
	OnChange(callback func(T)) Connection
	NotifyChange()
}

// ObservableMixin provides observable functionality via composition
type ObservableMixin[T any] struct {
	signal *Signal[T]
	self   T
}

func NewObservableMixin[T any](self T) *ObservableMixin[T] {
	return &ObservableMixin[T]{
		signal: NewSignal[T](),
		self:   self,
	}
}

func (o *ObservableMixin[T]) OnChange(callback func(T)) Connection {
	return o.signal.Connect(callback)
}

func (o *ObservableMixin[T]) NotifyChange() {
	o.signal.Emit(o.self)
}

// Timer provides periodic or one-shot timer functionality
type Timer struct {
	running atomic.Bool
	stopCh  chan struct{}
	mutex   sync.Mutex
	wg      sync.WaitGroup
	OnTick  func()
}

func NewTimer() *Timer {
	return &Timer{
		stopCh: make(chan struct{}),
	}
}

func (t *Timer) Start(interval time.Duration, repeat bool) {
	t.Stop()

	t.running.Store(true)
	t.stopCh = make(chan struct{})
	t.wg.Add(1)

	go func() {
		defer t.wg.Done()

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if !t.running.Load() {
					return
				}
				if t.OnTick != nil {
					t.OnTick()
				}
				if !repeat {
					return
				}
			case <-t.stopCh:
				return
			}
		}
	}()
}

func (t *Timer) Stop() {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if t.running.Load() {
		t.running.Store(false)
		close(t.stopCh)
		t.wg.Wait()
	}
}

func (t *Timer) Close() {
	t.Stop()
}
