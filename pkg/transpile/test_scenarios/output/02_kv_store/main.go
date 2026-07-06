//go:build ignore
// +build ignore

package main

import (
	"fmt"
	"os"
)

func printEntry(key string, val *KVValue, user interface{}) {
	fmt.Printf("  %s -> ", key)
	switch val.Type {
	case KVTypeString:
		if val.StrVal != nil {
			fmt.Printf("\"%s\"\n", *val.StrVal)
		} else {
			fmt.Printf("\"(null)\"\n")
		}
	case KVTypeInt:
		fmt.Printf("%d\n", val.IntVal)
	case KVTypeList:
		fmt.Printf("[list]\n")
	}
}

func main() {
	db := KVCreate()
	if db == nil {
		fmt.Fprintf(os.Stderr, "Failed to create store\n")
		os.Exit(1)
	}
	defer db.Destroy()

	// String operations
	fmt.Println("=== String Operations ===")
	db.Set("name", "togo")
	db.Set("version", "1.0.0")
	db.Set("author", "developer")

	nameVal := db.Get("name")
	if nameVal != nil {
		fmt.Printf("name    = %s\n", *nameVal)
	} else {
		fmt.Printf("name    = (nil)\n")
	}

	versionVal := db.Get("version")
	if versionVal != nil {
		fmt.Printf("version = %s\n", *versionVal)
	} else {
		fmt.Printf("version = (nil)\n")
	}

	missingVal := db.Get("missing")
	if missingVal != nil {
		fmt.Printf("missing = %s\n", *missingVal)
	} else {
		fmt.Printf("missing = (nil)\n")
	}

	// Integer operations
	fmt.Println("\n=== Integer Operations ===")
	db.SetInt("counter", 0)
	fmt.Printf("counter = %d\n", db.GetInt("counter", 0))
	db.Incr("counter")
	db.Incr("counter")
	db.IncrBy("counter", 10)
	fmt.Printf("counter after incr = %d\n", db.GetInt("counter", 0))

	// List operations
	fmt.Println("\n=== List Operations ===")
	db.LPush("tasks", "write tests")
	db.LPush("tasks", "review PR")
	db.RPush("tasks", "deploy")
	fmt.Printf("tasks length = %d\n", db.LLen("tasks"))

	task := db.LPop("tasks")
	if task != nil {
		fmt.Printf("popped: %s\n", *task)
	}
	fmt.Printf("tasks length after pop = %d\n", db.LLen("tasks"))

	// Delete
	fmt.Println("\n=== Delete ===")
	fmt.Printf("count before delete = %d\n", db.Count())
	db.Del("author")
	fmt.Printf("count after delete  = %d\n", db.Count())
	fmt.Printf("exists(author)  = %d\n", boolToInt(db.Exists("author")))
	fmt.Printf("exists(name)    = %d\n", boolToInt(db.Exists("name")))

	// Iterate
	fmt.Println("\n=== All Entries ===")
	db.ForEach(printEntry, nil)

	// Dump internal state
	fmt.Println("\n=== Internal State ===")
	db.Dump(os.Stdout)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
