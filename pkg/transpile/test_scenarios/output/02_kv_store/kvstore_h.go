//go:build ignore
// +build ignore

package kvstore

import (
	"fmt"
	"io"
	"os"
	"time"
)

const (
	KVInitialCapacity = 16
	KVLoadFactor      = 0.75
	KVOk              = 0
	KVErr             = -1
	KVNotFound        = -2
)

type KVType int

const (
	KVTypeString KVType = iota
	KVTypeInt
	KVTypeList
)

// ListNode is a singly-linked list node for list values
type ListNode struct {
	data string
	next *ListNode
}

// KVValue holds different types of values
type KVValue struct {
	typ       KVType
	strVal    string
	intVal    int64
	listVal   *ListNode
	expiresAt time.Time // zero value = no expiry
}

// KVEntry is a hash table entry
type KVEntry struct {
	key   string
	value KVValue
	next  *KVEntry
}

// KVStore is the in-memory key-value store
type KVStore struct {
	buckets      []*KVEntry
	capacity     int
	size         int
	expiredCount int
}

// KVIterFn is a callback for iterating over entries
type KVIterFn func(key string, value *KVValue, user interface{})

// Create creates a new KVStore
func Create() *KVStore {
	return &KVStore{
		buckets:      make([]*KVEntry, KVInitialCapacity),
		capacity:     KVInitialCapacity,
		size:         0,
		expiredCount: 0,
	}
}

// Destroy cleans up the KVStore
func (store *KVStore) Destroy() {
	if store == nil {
		return
	}
	for i := 0; i < store.capacity; i++ {
		entry := store.buckets[i]
		for entry != nil {
			next := entry.next
			freeListValue(&entry.value)
			entry = next
		}
	}
	store.buckets = nil
}

func freeListValue(value *KVValue) {
	if value.typ == KVTypeList {
		node := value.listVal
		for node != nil {
			next := node.next
			node = next
		}
	}
}

func hash(key string) uint32 {
	h := uint32(5381)
	for i := 0; i < len(key); i++ {
		h = ((h << 5) + h) + uint32(key[i])
	}
	return h
}

func (store *KVStore) isExpired(value *KVValue) bool {
	if value.expiresAt.IsZero() {
		return false
	}
	return time.Now().After(value.expiresAt)
}

func (store *KVStore) resize() {
	newCapacity := store.capacity * 2
	newBuckets := make([]*KVEntry, newCapacity)

	for i := 0; i < store.capacity; i++ {
		entry := store.buckets[i]
		for entry != nil {
			next := entry.next
			idx := hash(entry.key) % uint32(newCapacity)
			entry.next = newBuckets[idx]
			newBuckets[idx] = entry
			entry = next
		}
	}

	store.buckets = newBuckets
	store.capacity = newCapacity
}

func (store *KVStore) findEntry(key string) (*KVEntry, *KVEntry) {
	idx := hash(key) % uint32(store.capacity)
	var prev *KVEntry
	entry := store.buckets[idx]

	for entry != nil {
		if entry.key == key {
			return entry, prev
		}
		prev = entry
		entry = entry.next
	}
	return nil, prev
}

func (store *KVStore) setInternal(key string, value KVValue) int {
	entry, _ := store.findEntry(key)

	if entry != nil {
		freeListValue(&entry.value)
		entry.value = value
		return KVOk
	}

	if float64(store.size+1) > float64(store.capacity)*KVLoadFactor {
		store.resize()
	}

	idx := hash(key) % uint32(store.capacity)
	newEntry := &KVEntry{
		key:   key,
		value: value,
		next:  store.buckets[idx],
	}
	store.buckets[idx] = newEntry
	store.size++
	return KVOk
}

// Set sets a string value
func (store *KVStore) Set(key string, value string) int {
	return store.setInternal(key, KVValue{
		typ:    KVTypeString,
		strVal: value,
	})
}

// Setex sets a string value with expiration
func (store *KVStore) Setex(key string, value string, ttlSeconds int) int {
	expiresAt := time.Now().Add(time.Duration(ttlSeconds) * time.Second)
	return store.setInternal(key, KVValue{
		typ:       KVTypeString,
		strVal:    value,
		expiresAt: expiresAt,
	})
}

// Get retrieves a string value
func (store *KVStore) Get(key string) string {
	entry, _ := store.findEntry(key)
	if entry == nil {
		return ""
	}

	if store.isExpired(&entry.value) {
		store.Del(key)
		return ""
	}

	if entry.value.typ != KVTypeString {
		return ""
	}

	return entry.value.strVal
}

// Del deletes a key
func (store *KVStore) Del(key string) int {
	idx := hash(key) % uint32(store.capacity)
	var prev *KVEntry
	entry := store.buckets[idx]

	for entry != nil {
		if entry.key == key {
			if prev == nil {
				store.buckets[idx] = entry.next
			} else {
				prev.next = entry.next
			}
			freeListValue(&entry.value)
			store.size--
			return KVOk
		}
		prev = entry
		entry = entry.next
	}

	return KVNotFound
}

// Exists checks if a key exists
func (store *KVStore) Exists(key string) int {
	entry, _ := store.findEntry(key)
	if entry == nil {
		return 0
	}

	if store.isExpired(&entry.value) {
		store.Del(key)
		return 0
	}

	return 1
}

// SetInt sets an integer value
func (store *KVStore) SetInt(key string, value int64) int {
	return store.setInternal(key, KVValue{
		typ:    KVTypeInt,
		intVal: value,
	})
}

// GetInt retrieves an integer value
func (store *KVStore) GetInt(key string, defaultVal int64) int64 {
	entry, _ := store.findEntry(key)
	if entry == nil {
		return defaultVal
	}

	if store.isExpired(&entry.value) {
		store.Del(key)
		return defaultVal
	}

	if entry.value.typ != KVTypeInt {
		return defaultVal
	}

	return entry.value.intVal
}

// Incr increments an integer value by 1
func (store *KVStore) Incr(key string) int64 {
	return store.Incrby(key, 1)
}

// Incrby increments an integer value by delta
func (store *KVStore) Incrby(key string, delta int64) int64 {
	entry, _ := store.findEntry(key)

	if entry == nil {
		store.SetInt(key, delta)
		return delta
	}

	if entry.value.typ != KVTypeInt {
		store.SetInt(key, delta)
		return delta
	}

	entry.value.intVal += delta
	return entry.value.intVal
}

// Lpush prepends a value to a list
func (store *KVStore) Lpush(key string, value string) int {
	entry, _ := store.findEntry(key)

	if entry == nil {
		node := &ListNode{data: value, next: nil}
		store.setInternal(key, KVValue{
			typ:     KVTypeList,
			listVal: node,
		})
		return KVOk
	}

	if entry.value.typ != KVTypeList {
		return KVErr
	}

	node := &ListNode{data: value, next: entry.value.listVal}
	entry.value.listVal = node
	return KVOk
}

// Rpush appends a value to a list
func (store *KVStore) Rpush(key string, value string) int {
	entry, _ := store.findEntry(key)

	if entry == nil {
		node := &ListNode{data: value, next: nil}
		store.setInternal(key, KVValue{
			typ:     KVTypeList,
			listVal: node,
		})
		return KVOk
	}

	if entry.value.typ != KVTypeList {
		return KVErr
	}

	node := &ListNode{data: value, next: nil}

	if entry.value.listVal == nil {
		entry.value.listVal = node
		return KVOk
	}

	current := entry.value.listVal
	for current.next != nil {
		current = current.next
	}
	current.next = node
	return KVOk
}

// Lpop removes and returns the first element from a list
func (store *KVStore) Lpop(key string) string {
	entry, _ := store.findEntry(key)
	if entry == nil {
		return ""
	}

	if entry.value.typ != KVTypeList || entry.value.listVal == nil {
		return ""
	}

	node := entry.value.listVal
	data := node.data
	entry.value.listVal = node.next

	if entry.value.listVal == nil {
		store.Del(key)
	}

	return data
}

// Llen returns the length of a list
func (store *KVStore) Llen(key string) int {
	entry, _ := store.findEntry(key)
	if entry == nil {
		return 0
	}

	if entry.value.typ != KVTypeList {
		return 0
	}

	count := 0
	node := entry.value.listVal
	for node != nil {
		count++
		node = node.next
	}
	return count
}

// Count returns the number of keys in the store
func (store *KVStore) Count() int {
	return store.size
}

// Foreach iterates over all entries
func (store *KVStore) Foreach(callback KVIterFn, user interface{}) {
	for i := 0; i < store.capacity; i++ {
		entry := store.buckets[i]
		for entry != nil {
			if !store.isExpired(&entry.value) {
				callback(entry.key, &entry.value, user)
			}
			entry = entry.next
		}
	}
}

// ExpireCheck removes expired entries
func (store *KVStore) ExpireCheck() {
	for i := 0; i < store.capacity; i++ {
		entry := store.buckets[i]
		for entry != nil {
			next := entry.next
			if store.isExpired(&entry.value) {
				store.Del(entry.key)
				store.expiredCount++
			}
			entry = next
		}
	}
}

// Dump outputs the store contents
func (store *KVStore) Dump(out io.Writer) {
	if out == nil {
		out = os.Stdout
	}

	fmt.Fprintf(out, "KVStore: size=%d, capacity=%d, expired=%d\n",
		store.size, store.capacity, store.expiredCount)

	for i := 0; i < store.capacity; i++ {
		entry := store.buckets[i]
		for entry != nil {
			if store.isExpired(&entry.value) {
				entry = entry.next
				continue
			}

			switch entry.value.typ {
			case KVTypeString:
				fmt.Fprintf(out, "  %s = \"%s\" (string)\n", entry.key, entry.value.strVal)
			case KVTypeInt:
				fmt.Fprintf(out, "  %s = %d (int)\n", entry.key, entry.value.intVal)
			case KVTypeList:
				fmt.Fprintf(out, "  %s = [", entry.key)
				node := entry.value.listVal
				first := true
				for node != nil {
					if !first {
						fmt.Fprintf(out, ", ")
					}
					fmt.Fprintf(out, "\"%s\"", node.data)
					first = false
					node = node.next
				}
				fmt.Fprintf(out, "] (list)\n")
			}

			if !entry.value.expiresAt.IsZero() {
				fmt.Fprintf(out, "    expires: %s\n", entry.value.expiresAt.Format(time.RFC3339))
			}

			entry = entry.next
		}
	}
}
