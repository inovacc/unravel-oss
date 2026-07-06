/*
 * main.c - Redis-style key-value store demo
 */
#include "kvstore.h"

static void print_entry(const char* key, const KVValue* val, void* user) {
    (void)user;
    printf("  %s -> ", key);
    switch (val->type) {
    case KV_TYPE_STRING:
        printf("\"%s\"\n", val->str_val ? val->str_val : "(null)");
        break;
    case KV_TYPE_INT:
        printf("%lld\n", (long long)val->int_val);
        break;
    case KV_TYPE_LIST:
        printf("[list]\n");
        break;
    }
}

int main(void) {
    KVStore* db = kv_create();
    if (!db) {
        fprintf(stderr, "Failed to create store\n");
        return 1;
    }

    /* String operations */
    printf("=== String Operations ===\n");
    kv_set(db, "name", "togo");
    kv_set(db, "version", "1.0.0");
    kv_set(db, "author", "developer");

    printf("name    = %s\n", kv_get(db, "name"));
    printf("version = %s\n", kv_get(db, "version"));
    printf("missing = %s\n", kv_get(db, "missing") ? kv_get(db, "missing") : "(nil)");

    /* Integer operations */
    printf("\n=== Integer Operations ===\n");
    kv_set_int(db, "counter", 0);
    printf("counter = %lld\n", (long long)kv_get_int(db, "counter", 0));
    kv_incr(db, "counter");
    kv_incr(db, "counter");
    kv_incrby(db, "counter", 10);
    printf("counter after incr = %lld\n", (long long)kv_get_int(db, "counter", 0));

    /* List operations */
    printf("\n=== List Operations ===\n");
    kv_lpush(db, "tasks", "write tests");
    kv_lpush(db, "tasks", "review PR");
    kv_rpush(db, "tasks", "deploy");
    printf("tasks length = %d\n", kv_llen(db, "tasks"));

    char* task = kv_lpop(db, "tasks");
    if (task) {
        printf("popped: %s\n", task);
        free(task);
    }
    printf("tasks length after pop = %d\n", kv_llen(db, "tasks"));

    /* Delete */
    printf("\n=== Delete ===\n");
    printf("count before delete = %zu\n", kv_count(db));
    kv_del(db, "author");
    printf("count after delete  = %zu\n", kv_count(db));
    printf("exists(author)  = %d\n", kv_exists(db, "author"));
    printf("exists(name)    = %d\n", kv_exists(db, "name"));

    /* Iterate */
    printf("\n=== All Entries ===\n");
    kv_foreach(db, print_entry, NULL);

    /* Dump internal state */
    printf("\n=== Internal State ===\n");
    kv_dump(db, stdout);

    kv_destroy(db);
    return 0;
}
