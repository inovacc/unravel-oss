/*
 * kvstore.c - In-memory key-value store implementation
 * Inspired by Redis dict.c
 */
#include "kvstore.h"

/* DJB2 hash function */
static uint32_t hash_key(const char* key) {
    uint32_t hash = 5381;
    int c;
    while ((c = *key++))
        hash = ((hash << 5) + hash) + (uint32_t)c;
    return hash;
}

static char* str_dup(const char* s) {
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char* copy = (char*)malloc(len);
    if (copy)
        memcpy(copy, s, len);
    return copy;
}

static void free_list(ListNode* head) {
    while (head) {
        ListNode* next = head->next;
        free(head->data);
        free(head);
        head = next;
    }
}

static void free_value(KVValue* val) {
    switch (val->type) {
    case KV_TYPE_STRING:
        free(val->str_val);
        val->str_val = NULL;
        break;
    case KV_TYPE_LIST:
        free_list(val->list_val);
        val->list_val = NULL;
        break;
    case KV_TYPE_INT:
        break;
    }
}

static int is_expired(const KVValue* val) {
    if (val->expires_at == 0)
        return 0;
    return time(NULL) >= val->expires_at;
}

/* Resize the hash table when load factor exceeded */
static int kv_resize(KVStore* store) {
    size_t new_cap = store->capacity * 2;
    KVEntry** new_buckets = (KVEntry**)calloc(new_cap, sizeof(KVEntry*));
    if (!new_buckets)
        return KV_ERR;

    /* Rehash all entries */
    for (size_t i = 0; i < store->capacity; i++) {
        KVEntry* entry = store->buckets[i];
        while (entry) {
            KVEntry* next = entry->next;
            uint32_t idx = hash_key(entry->key) % (uint32_t)new_cap;
            entry->next = new_buckets[idx];
            new_buckets[idx] = entry;
            entry = next;
        }
    }

    free(store->buckets);
    store->buckets = new_buckets;
    store->capacity = new_cap;
    return KV_OK;
}

/* Find entry by key, optionally removing expired entries */
static KVEntry* find_entry(KVStore* store, const char* key, KVEntry** prev_out) {
    uint32_t idx = hash_key(key) % (uint32_t)store->capacity;
    KVEntry* prev = NULL;
    KVEntry* entry = store->buckets[idx];

    while (entry) {
        if (strcmp(entry->key, key) == 0) {
            /* Lazy expiration */
            if (is_expired(&entry->value)) {
                /* Remove expired entry */
                if (prev)
                    prev->next = entry->next;
                else
                    store->buckets[idx] = entry->next;

                free(entry->key);
                free_value(&entry->value);
                free(entry);
                store->size--;
                store->expired_count++;
                return NULL;
            }
            if (prev_out)
                *prev_out = prev;
            return entry;
        }
        prev = entry;
        entry = entry->next;
    }
    return NULL;
}

KVStore* kv_create(void) {
    KVStore* store = (KVStore*)calloc(1, sizeof(KVStore));
    if (!store)
        return NULL;

    store->capacity = KV_INITIAL_CAPACITY;
    store->buckets = (KVEntry**)calloc(store->capacity, sizeof(KVEntry*));
    if (!store->buckets) {
        free(store);
        return NULL;
    }

    return store;
}

void kv_destroy(KVStore* store) {
    if (!store)
        return;

    for (size_t i = 0; i < store->capacity; i++) {
        KVEntry* entry = store->buckets[i];
        while (entry) {
            KVEntry* next = entry->next;
            free(entry->key);
            free_value(&entry->value);
            free(entry);
            entry = next;
        }
    }

    free(store->buckets);
    free(store);
}

int kv_set(KVStore* store, const char* key, const char* value) {
    return kv_setex(store, key, value, 0);
}

int kv_setex(KVStore* store, const char* key, const char* value,
             int ttl_seconds) {
    if (!store || !key)
        return KV_ERR;

    /* Check if key already exists */
    KVEntry* existing = find_entry(store, key, NULL);
    if (existing) {
        free_value(&existing->value);
        existing->value.type = KV_TYPE_STRING;
        existing->value.str_val = str_dup(value);
        existing->value.expires_at = ttl_seconds > 0 ?
            time(NULL) + ttl_seconds : 0;
        return KV_OK;
    }

    /* Check load factor and resize if needed */
    if ((double)store->size / (double)store->capacity >= KV_LOAD_FACTOR) {
        if (kv_resize(store) != KV_OK)
            return KV_ERR;
    }

    /* Create new entry */
    KVEntry* entry = (KVEntry*)calloc(1, sizeof(KVEntry));
    if (!entry)
        return KV_ERR;

    entry->key = str_dup(key);
    entry->value.type = KV_TYPE_STRING;
    entry->value.str_val = str_dup(value);
    entry->value.expires_at = ttl_seconds > 0 ? time(NULL) + ttl_seconds : 0;

    uint32_t idx = hash_key(key) % (uint32_t)store->capacity;
    entry->next = store->buckets[idx];
    store->buckets[idx] = entry;
    store->size++;

    return KV_OK;
}

const char* kv_get(KVStore* store, const char* key) {
    if (!store || !key)
        return NULL;

    KVEntry* entry = find_entry(store, key, NULL);
    if (!entry || entry->value.type != KV_TYPE_STRING)
        return NULL;

    return entry->value.str_val;
}

int kv_del(KVStore* store, const char* key) {
    if (!store || !key)
        return KV_ERR;

    uint32_t idx = hash_key(key) % (uint32_t)store->capacity;
    KVEntry* prev = NULL;
    KVEntry* entry = store->buckets[idx];

    while (entry) {
        if (strcmp(entry->key, key) == 0) {
            if (prev)
                prev->next = entry->next;
            else
                store->buckets[idx] = entry->next;

            free(entry->key);
            free_value(&entry->value);
            free(entry);
            store->size--;
            return KV_OK;
        }
        prev = entry;
        entry = entry->next;
    }

    return KV_NOT_FOUND;
}

int kv_exists(KVStore* store, const char* key) {
    return find_entry(store, key, NULL) != NULL;
}

int kv_set_int(KVStore* store, const char* key, int64_t value) {
    if (!store || !key)
        return KV_ERR;

    KVEntry* existing = find_entry(store, key, NULL);
    if (existing) {
        free_value(&existing->value);
        existing->value.type = KV_TYPE_INT;
        existing->value.int_val = value;
        existing->value.expires_at = 0;
        return KV_OK;
    }

    if ((double)store->size / (double)store->capacity >= KV_LOAD_FACTOR) {
        if (kv_resize(store) != KV_OK)
            return KV_ERR;
    }

    KVEntry* entry = (KVEntry*)calloc(1, sizeof(KVEntry));
    if (!entry)
        return KV_ERR;

    entry->key = str_dup(key);
    entry->value.type = KV_TYPE_INT;
    entry->value.int_val = value;

    uint32_t idx = hash_key(key) % (uint32_t)store->capacity;
    entry->next = store->buckets[idx];
    store->buckets[idx] = entry;
    store->size++;

    return KV_OK;
}

int64_t kv_get_int(KVStore* store, const char* key, int64_t default_val) {
    KVEntry* entry = find_entry(store, key, NULL);
    if (!entry || entry->value.type != KV_TYPE_INT)
        return default_val;
    return entry->value.int_val;
}

int64_t kv_incr(KVStore* store, const char* key) {
    return kv_incrby(store, key, 1);
}

int64_t kv_incrby(KVStore* store, const char* key, int64_t delta) {
    KVEntry* entry = find_entry(store, key, NULL);
    if (!entry) {
        kv_set_int(store, key, delta);
        return delta;
    }

    if (entry->value.type != KV_TYPE_INT) {
        /* Try to parse string as int */
        if (entry->value.type == KV_TYPE_STRING && entry->value.str_val) {
            char* endptr;
            int64_t val = strtoll(entry->value.str_val, &endptr, 10);
            if (*endptr == '\0') {
                free(entry->value.str_val);
                entry->value.type = KV_TYPE_INT;
                entry->value.int_val = val + delta;
                return entry->value.int_val;
            }
        }
        return 0; /* Cannot increment non-integer */
    }

    entry->value.int_val += delta;
    return entry->value.int_val;
}

int kv_lpush(KVStore* store, const char* key, const char* value) {
    if (!store || !key || !value)
        return KV_ERR;

    KVEntry* entry = find_entry(store, key, NULL);

    ListNode* node = (ListNode*)malloc(sizeof(ListNode));
    if (!node)
        return KV_ERR;
    node->data = str_dup(value);

    if (entry) {
        if (entry->value.type != KV_TYPE_LIST)
            return KV_ERR;
        node->next = entry->value.list_val;
        entry->value.list_val = node;
    } else {
        node->next = NULL;

        KVEntry* new_entry = (KVEntry*)calloc(1, sizeof(KVEntry));
        if (!new_entry) {
            free(node->data);
            free(node);
            return KV_ERR;
        }
        new_entry->key = str_dup(key);
        new_entry->value.type = KV_TYPE_LIST;
        new_entry->value.list_val = node;

        uint32_t idx = hash_key(key) % (uint32_t)store->capacity;
        new_entry->next = store->buckets[idx];
        store->buckets[idx] = new_entry;
        store->size++;
    }

    return KV_OK;
}

int kv_rpush(KVStore* store, const char* key, const char* value) {
    if (!store || !key || !value)
        return KV_ERR;

    KVEntry* entry = find_entry(store, key, NULL);

    ListNode* node = (ListNode*)malloc(sizeof(ListNode));
    if (!node)
        return KV_ERR;
    node->data = str_dup(value);
    node->next = NULL;

    if (entry) {
        if (entry->value.type != KV_TYPE_LIST)
            return KV_ERR;

        if (!entry->value.list_val) {
            entry->value.list_val = node;
        } else {
            ListNode* tail = entry->value.list_val;
            while (tail->next)
                tail = tail->next;
            tail->next = node;
        }
    } else {
        KVEntry* new_entry = (KVEntry*)calloc(1, sizeof(KVEntry));
        if (!new_entry) {
            free(node->data);
            free(node);
            return KV_ERR;
        }
        new_entry->key = str_dup(key);
        new_entry->value.type = KV_TYPE_LIST;
        new_entry->value.list_val = node;

        uint32_t idx = hash_key(key) % (uint32_t)store->capacity;
        new_entry->next = store->buckets[idx];
        store->buckets[idx] = new_entry;
        store->size++;
    }

    return KV_OK;
}

char* kv_lpop(KVStore* store, const char* key) {
    KVEntry* entry = find_entry(store, key, NULL);
    if (!entry || entry->value.type != KV_TYPE_LIST || !entry->value.list_val)
        return NULL;

    ListNode* head = entry->value.list_val;
    entry->value.list_val = head->next;

    char* data = head->data;
    free(head);
    return data;  /* Caller must free */
}

int kv_llen(KVStore* store, const char* key) {
    KVEntry* entry = find_entry(store, key, NULL);
    if (!entry || entry->value.type != KV_TYPE_LIST)
        return 0;

    int count = 0;
    ListNode* node = entry->value.list_val;
    while (node) {
        count++;
        node = node->next;
    }
    return count;
}

size_t kv_count(const KVStore* store) {
    return store ? store->size : 0;
}

void kv_foreach(KVStore* store, kv_iter_fn callback, void* user) {
    if (!store || !callback)
        return;

    for (size_t i = 0; i < store->capacity; i++) {
        KVEntry* entry = store->buckets[i];
        while (entry) {
            KVEntry* next = entry->next;  /* Save in case callback modifies */
            if (!is_expired(&entry->value)) {
                callback(entry->key, &entry->value, user);
            }
            entry = next;
        }
    }
}

void kv_expire_check(KVStore* store) {
    if (!store)
        return;

    for (size_t i = 0; i < store->capacity; i++) {
        KVEntry* prev = NULL;
        KVEntry* entry = store->buckets[i];
        while (entry) {
            KVEntry* next = entry->next;
            if (is_expired(&entry->value)) {
                if (prev)
                    prev->next = next;
                else
                    store->buckets[i] = next;

                free(entry->key);
                free_value(&entry->value);
                free(entry);
                store->size--;
                store->expired_count++;
            } else {
                prev = entry;
            }
            entry = next;
        }
    }
}

void kv_dump(const KVStore* store, FILE* out) {
    if (!store || !out)
        return;

    fprintf(out, "KVStore: %zu entries, %zu capacity, %zu expired\n",
            store->size, store->capacity, store->expired_count);

    for (size_t i = 0; i < store->capacity; i++) {
        KVEntry* entry = store->buckets[i];
        while (entry) {
            fprintf(out, "  [%zu] %s = ", i, entry->key);
            switch (entry->value.type) {
            case KV_TYPE_STRING:
                fprintf(out, "\"%s\"", entry->value.str_val ? entry->value.str_val : "");
                break;
            case KV_TYPE_INT:
                fprintf(out, "%lld", (long long)entry->value.int_val);
                break;
            case KV_TYPE_LIST: {
                fprintf(out, "[");
                ListNode* n = entry->value.list_val;
                while (n) {
                    fprintf(out, "\"%s\"", n->data);
                    if (n->next) fprintf(out, ", ");
                    n = n->next;
                }
                fprintf(out, "]");
                break;
            }
            }
            if (entry->value.expires_at > 0)
                fprintf(out, " (TTL)");
            fprintf(out, "\n");
            entry = entry->next;
        }
    }
}
