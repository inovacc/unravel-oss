/*
 * kvstore.h - In-memory key-value store with hash table
 * Inspired by Redis dict.h
 */
#ifndef KVSTORE_H
#define KVSTORE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#define KV_INITIAL_CAPACITY 16
#define KV_LOAD_FACTOR      0.75
#define KV_OK               0
#define KV_ERR             -1
#define KV_NOT_FOUND       -2

typedef enum {
    KV_TYPE_STRING,
    KV_TYPE_INT,
    KV_TYPE_LIST
} KVType;

/* Singly-linked list node for list values */
typedef struct ListNode {
    char* data;
    struct ListNode* next;
} ListNode;

/* A value can hold different types */
typedef struct {
    KVType type;
    union {
        char*     str_val;
        int64_t   int_val;
        ListNode* list_val;
    };
    time_t expires_at;  /* 0 = no expiry */
} KVValue;

/* Hash table entry */
typedef struct KVEntry {
    char*           key;
    KVValue         value;
    struct KVEntry* next;  /* Chaining for collisions */
} KVEntry;

/* The store itself */
typedef struct {
    KVEntry** buckets;
    size_t    capacity;
    size_t    size;
    size_t    expired_count;
} KVStore;

/* Callback for iterating over entries */
typedef void (*kv_iter_fn)(const char* key, const KVValue* value, void* user);

/* Lifecycle */
KVStore* kv_create(void);
void     kv_destroy(KVStore* store);

/* String operations */
int         kv_set(KVStore* store, const char* key, const char* value);
int         kv_setex(KVStore* store, const char* key, const char* value, int ttl_seconds);
const char* kv_get(KVStore* store, const char* key);
int         kv_del(KVStore* store, const char* key);
int         kv_exists(KVStore* store, const char* key);

/* Integer operations */
int     kv_set_int(KVStore* store, const char* key, int64_t value);
int64_t kv_get_int(KVStore* store, const char* key, int64_t default_val);
int64_t kv_incr(KVStore* store, const char* key);
int64_t kv_incrby(KVStore* store, const char* key, int64_t delta);

/* List operations */
int         kv_lpush(KVStore* store, const char* key, const char* value);
int         kv_rpush(KVStore* store, const char* key, const char* value);
char*       kv_lpop(KVStore* store, const char* key);
int         kv_llen(KVStore* store, const char* key);

/* Utility */
size_t kv_count(const KVStore* store);
void   kv_foreach(KVStore* store, kv_iter_fn callback, void* user);
void   kv_expire_check(KVStore* store);
void   kv_dump(const KVStore* store, FILE* out);

#endif /* KVSTORE_H */
