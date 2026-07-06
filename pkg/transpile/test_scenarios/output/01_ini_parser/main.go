//go:build ignore
// +build ignore

package main

import (
	"fmt"
	"os"
)

func main() {
	filename := "config.ini"
	if len(os.Args) > 1 {
		filename = os.Args[1]
	}

	config := iniLoad(filename)
	if config == nil {
		fmt.Fprintf(os.Stderr, "Error: failed to allocate config\n")
		os.Exit(1)
	}

	if config.Error != "" {
		fmt.Fprintf(os.Stderr, "Warning: %s\n", config.Error)
	}

	fmt.Println("=== Database Configuration ===")
	host := iniGet(config, "database", "host")
	port := iniGetInt(config, "database", "port", 5432)
	dbname := iniGet(config, "database", "name")
	ssl := iniGetBool(config, "database", "ssl", false)

	if host != "" {
		fmt.Printf("Host: %s\n", host)
	} else {
		fmt.Printf("Host: (not set)\n")
	}
	fmt.Printf("Port: %d\n", port)
	if dbname != "" {
		fmt.Printf("Database: %s\n", dbname)
	} else {
		fmt.Printf("Database: (not set)\n")
	}
	if ssl {
		fmt.Printf("SSL: enabled\n")
	} else {
		fmt.Printf("SSL: disabled\n")
	}

	fmt.Println("\n=== Server Configuration ===")
	addr := iniGet(config, "server", "listen")
	workers := iniGetInt(config, "server", "workers", 4)
	debug := iniGetBool(config, "server", "debug", false)

	if addr != "" {
		fmt.Printf("Listen: %s\n", addr)
	} else {
		fmt.Printf("Listen: 0.0.0.0:8080\n")
	}
	fmt.Printf("Workers: %d\n", workers)
	if debug {
		fmt.Printf("Debug: yes\n")
	} else {
		fmt.Printf("Debug: no\n")
	}

	iniFree(config)
}
