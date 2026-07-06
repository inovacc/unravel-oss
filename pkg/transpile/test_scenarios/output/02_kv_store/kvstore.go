//go:build ignore
// +build ignore

/*
 * kvstore.go - In-memory key-value store implementation
 * Inspired by Redis dict.c
 */
package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"time"
)

const (
	KVInitialCapacity = 16
	KVLoadFactor      = 0.75
	KVOK              = 0
	KVErr             = -1
	KVNotFound        = -2
)

type KVType int

const (
	KVTypeString KVType = iota
	KVTypeInt
	KVTypeList
)

type ListNode struct {
	data string
	next *ListNode
}

type KVValue struct {
	typ       KVType
	strVal    string
	intVal    int64
	listVal   *ListNode
	expiresAt int64
}

type KVEntry struct {
	key   string
	value KVValue
	next  *KVEntry
}

type KVStore struct {
	buckets      []*KVEntry
	size         uint
	capacity     uint
	expiredCount uint
}

type KVIterFn func(key string, value *KVValue, user interface{})

// DJB2 hash function
func hashKey(key string) uint32 {
	hash := uint32(5381)
	for i := 0; i < len(key); i++ {
		c := uint32(key[i])
		hash = ((hash << 5) + hash) + c
	}
	return hash
}

func freeList(head *ListNode) {
	for head != nil {
		next := head.next
		head = next
	}
}

func freeValue(val *KVValue) {
	switch val.typ {
	case KVTypeString:
		val.strVal = ""
	case KVTypeList:
		freeList(val.listVal)
		val.listVal = nil
	case KVTypeInt:
		// nothing to free
	}
}

func isExpired(val *KVValue) bool {
	if val.expiresAt == 0 {
		return false
	}
	return time.Now().Unix() >= val.expiresAt
}

// Resize the hash table when load factor exceeded
func kvResize(store *KVStore) int {
	newCap := store.capacity * 2
	newBuckets := make([]*KVEntry, newCap)

	// Rehash all entries
	for i := uint(0); i < store.capacity; i++ {
		entry := store.buckets[i]
		for entry != nil {
			next := entry.next
			idx := hashKey(entry.key) % uint32(newCap)
			entry.next = newBuckets[idx]
			newBuckets[idx] = entry
			entry = next
		}
	}

	store.buckets = newBuckets
	store.capacity = newCap
	return KVOK
}

// Find entry by key, optionally removing expired entries
func findEntry(store *KVStore, key string, prevOut **KVEntry) *KVEntry {
	idx := hashKey(key) % uint32(store.capacity)
	var prev *KVEntry
	entry := store.buckets[idx]

	for entry != nil {
		if entry.key == key {
			// Lazy expiration
			if isExpired(&entry.value) {
				// Remove expired entry
				if prev != nil {
					prev.next = entry.next
				} else {
					store.buckets[idx] = entry.next
				}

				freeValue(&entry.value)
				store.size--
				store.expiredCount++
				return nil
			}
			if prevOut != nil {
				*prevOut = prev
			}
			return entry
		}
		prev = entry
		entry = entry.next
	}
	return nil
}

func KvCreate() *KVStore {
	store := &KVStore{
		capacity: KVInitialCapacity,
		buckets:  make([]*KVEntry, KVInitialCapacity),
	}
	return store
}

func KvDestroy(store *KVStore) {
	if store == nil {
		return
	}

	for i := uint(0); i < store.capacity; i++ {
		entry := store.buckets[i]
		for entry != nil {
			next := entry.next
			freeValue(&entry.value)
			entry = next
		}
	}
}

func KvSet(store *KVStore, key string, value string) int {
	return KvSetex(store, key, value, 0)
}

func KvSetex(store *KVStore, key string, value string, ttlSeconds int) int {
	if store == nil || key == "" {
		return KVErr
	}

	// Check if key already exists
	existing := findEntry(store, key, nil)
	if existing != nil {
		freeValue(&existing.value)
		existing.value.typ = KVTypeString
		existing.value.strVal = value
		if ttlSeconds > 0 {
			existing.value.expiresAt = time.Now().Unix() + int64(ttlSeconds)
		} else {
			existing.value.expiresAt = 0
		}
		return KVOK
	}

	// Check load factor and resize if needed
	if float64(store.size)/float64(store.capacity) >= KVLoadFactor {
		if kvResize(store) != KVOK {
			return KVErr
		}
	}

	// Create new entry
	entry := &KVEntry{
		key: key,
		value: KVValue{
			typ:    KVTypeString,
			strVal: value,
		},
	}
	if ttlSeconds > 0 {
		entry.value.expiresAt = time.Now().Unix() + int64(ttlSeconds)
	}

	idx := hashKey(key) % uint32(store.capacity)
	entry.next = store.buckets[idx]
	store.buckets[idx] = entry
	store.size++

	return KVOK
}

func KvGet(store *KVStore, key string) string {
	if store == nil || key == "" {
		return ""
	}

	entry := findEntry(store, key, nil)
	if entry == nil || entry.value.typ != KVTypeString {
		return ""
	}

	return entry.value.strVal
}

func KvDel(store *KVStore, key string) int {
	if store == nil || key == "" {
		return KVErr
	}

	idx := hashKey(key) % uint32(store.capacity)
	var prev *KVEntry
	entry := store.buckets[idx]

	for entry != nil {
		if entry.key == key {
			if prev != nil {
				prev.next = entry.next
			} else {
				store.buckets[idx] = entry.next
			}

			freeValue(&entry.value)
			store.size--
			return KVOK
		}
		prev = entry
		entry = entry.next
	}

	return KVNotFound
}

func KvExists(store *KVStore, key string) bool {
	return findEntry(store, key, nil) != nil
}

func KvSetInt(store *KVStore, key string, value int64) int {
	if store == nil || key == "" {
		return KVErr
	}

	existing := findEntry(store, key, nil)
	if existing != nil {
		freeValue(&existing.value)
		existing.value.typ = KVTypeInt
		existing.value.intVal = value
		existing.value.expiresAt = 0
		return KVOK
	}

	if float64(store.size)/float64(store.capacity) >= KVLoadFactor {
		if kvResize(store) != KVOK {
			return KVErr
		}
	}

	entry := &KVEntry{
		key: key,
		value: KVValue{
			typ:    KVTypeInt,
			intVal: value,
		},
	}

	idx := hashKey(key) % uint32(store.capacity)
	entry.next = store.buckets[idx]
	store.buckets[idx] = entry
	store.size++

	return KVOK
}

func KvGetInt(store *KVStore, key string, defaultVal int64) int64 {
	entry := findEntry(store, key, nil)
	if entry == nil || entry.value.typ != KVTypeInt {
		return defaultVal
	}
	return entry.value.intVal
}

func KvIncr(store *KVStore, key string) int64 {
	return KvIncrby(store, key, 1)
}

func KvIncrby(store *KVStore, key string, delta int64) int64 {
	entry := findEntry(store, key, nil)
	if entry == nil {
		KvSetInt(store, key, delta)
		return delta
	}

	if entry.value.typ != KVTypeInt {
		// Try to parse string as int
		if entry.value.typ == KVTypeString && entry.value.strVal != "" {
			val, err := strconv.ParseInt(entry.value.strVal, 10, 64)
			if err == nil {
				entry.value.typ = KVTypeInt
				entry.value.intVal = val + delta
				entry.value.strVal = ""
				return entry.value.intVal
			}
		}
		return 0 // Cannot increment non-integer
	}

	entry.value.intVal += delta
	return entry.value.intVal
}

func KvLpush(store *KVStore, key string, value string) int {
	if store == nil || key == "" || value == "" {
		return KVErr
	}

	entry := findEntry(store, key, nil)

	node := &ListNode{
		data: value,
	}

	if entry != nil {
		if entry.value.typ != KVTypeList {
			return KVErr
		}
		node.next = entry.value.listVal
		entry.value.listVal = node
	} else {
		newEntry := &KVEntry{
			key: key,
			value: KVValue{
				typ:     KVTypeList,
				listVal: node,
			},
		}

		idx := hashKey(key) % uint32(store.capacity)
		newEntry.next = store.buckets[idx]
		store.buckets[idx] = newEntry
		store.size++
	}

	return KVOK
}

func KvRpush(store *KVStore, key string, value string) int {
	if store == nil || key == "" || value == "" {
		return KVErr
	}

	entry := findEntry(store, key, nil)

	node := &ListNode{
		data: value,
		next: nil,
	}

	if entry != nil {
		if entry.value.typ != KVTypeList {
			return KVErr
		}

		if entry.value.listVal == nil {
			entry.value.listVal = node
		} else {
			tail := entry.value.listVal
			for tail.next != nil {
				tail = tail.next
			}
			tail.next = node
		}
	} else {
		newEntry := &KVEntry{
			key: key,
			value: KVValue{
				typ:     KVTypeList,
				listVal: node,
			},
		}

		idx := hashKey(key) % uint32(store.capacity)
		newEntry.next = store.buckets[idx]
		store.buckets[idx] = newEntry
		store.size++
	}

	return KVOK
}

func KvLpop(store *KVStore, key string) string {
	entry := findEntry(store, key, nil)
	if entry == nil || entry.value.typ != KVTypeList || entry.value.listVal == nil {
		return ""
	}

	head := entry.value.listVal
	entry.value.listVal = head.next

	data := head.data
	return data
}

func KvLlen(store *KVStore, key string) int {
	entry := findEntry(store, key, nil)
	if entry == nil || entry.value.typ != KVTypeList {
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

func KvCount(store *KVStore) uint {
	if store == nil {
		return 0
	}
	return store.size
}

func KvForeach(store *KVStore, callback KVIterFn, user interface{}) {
	if store == nil || callback == nil {
		return
	}

	for i := uint(0); i < store.capacity; i++ {
		entry := store.buckets[i]
		for entry != nil {
			next := entry.next // Save in case callback modifies
			if !isExpired(&entry.value) {
				callback(entry.key, &entry.value, user)
			}
			entry = next
		}
	}
}

func KvExpireCheck(store *KVStore) {
	if store == nil {
		return
	}

	for i := uint(0); i < store.capacity; i++ {
		var prev *KVEntry
		entry := store.buckets[i]
		for entry != nil {
			next := entry.next
			if isExpired(&entry.value) {
				if prev != nil {
					prev.next = next
				} else {
					store.buckets[i] = next
				}

				freeValue(&entry.value)
				store.size--
				store.expiredCount++
			} else {
				prev = entry
			}
			entry = next
		}
	}
}

func KvDump(store *KVStore, out io.Writer) {
	if store == nil || out == nil {
		return
	}

	fmt.Fprintf(out, "KVStore: %d entries, %d capacity, %d expired\n",
		store.size, store.capacity, store.expiredCount)

	for i := uint(0); i < store.capacity; i++ {
		entry := store.buckets[i]
		for entry != nil {
			fmt.Fprintf(out, "  [%d] %s = ", i, entry.key)
			switch entry.value.typ {
			case KVTypeString:
				fmt.Fprintf(out, "\"%s\"", entry.value.strVal)
			case KVTypeInt:
				fmt.Fprintf(out, "%d", entry.value.intVal)
			case KVTypeList:
				fmt.Fprintf(out, "[")
				n := entry.value.listVal
				for n != nil {
					fmt.Fprintf(out, "\"%s\"", n.data)
					if n.next != nil {
						fmt.Fprintf(out, ", ")
					}
					n = n.next
				}
				fmt.Fprintf(out, "]")
			}
			if entry.value.expiresAt > 0 {
				fmt.Fprintf(out, " (TTL)")
			}
			fmt.Fprintf(out, "\n")
			entry = entry.next
		}
	}
}

func main() {
	store := KvCreate()
	defer KvDestroy(store)

	KvSet(store, "key1", "value1")
	KvSetInt(store, "counter", 42)
	KvLpush(store, "list1", "item1")
	KvLpush(store, "list1", "item2")

	KvDump(store, os.Stdout)
}
