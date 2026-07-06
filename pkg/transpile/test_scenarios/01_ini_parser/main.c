/*
 * main.c - INI parser demo: load a config and print database settings
 */
#include "ini_parser.h"

int main(int argc, char* argv[]) {
    const char* filename = "config.ini";
    if (argc > 1)
        filename = argv[1];

    IniConfig* config = ini_load(filename);
    if (!config) {
        fprintf(stderr, "Error: failed to allocate config\n");
        return 1;
    }

    if (config->error[0] != '\0') {
        fprintf(stderr, "Warning: %s\n", config->error);
    }

    printf("=== Database Configuration ===\n");
    const char* host = ini_get(config, "database", "host");
    int port = ini_get_int(config, "database", "port", 5432);
    const char* dbname = ini_get(config, "database", "name");
    int ssl = ini_get_bool(config, "database", "ssl", 0);

    printf("Host: %s\n", host ? host : "(not set)");
    printf("Port: %d\n", port);
    printf("Database: %s\n", dbname ? dbname : "(not set)");
    printf("SSL: %s\n", ssl ? "enabled" : "disabled");

    printf("\n=== Server Configuration ===\n");
    const char* addr = ini_get(config, "server", "listen");
    int workers = ini_get_int(config, "server", "workers", 4);
    int debug = ini_get_bool(config, "server", "debug", 0);

    printf("Listen: %s\n", addr ? addr : "0.0.0.0:8080");
    printf("Workers: %d\n", workers);
    printf("Debug: %s\n", debug ? "yes" : "no");

    ini_free(config);
    return 0;
}
