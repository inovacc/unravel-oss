/*
 * ini_parser.h - Simple INI file parser
 * Inspired by inih (https://github.com/benhoyt/inih)
 */
#ifndef INI_PARSER_H
#define INI_PARSER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define INI_MAX_LINE    256
#define INI_MAX_SECTION 64
#define INI_MAX_NAME    64
#define INI_MAX_ENTRIES 128

typedef struct {
    char section[INI_MAX_SECTION];
    char name[INI_MAX_NAME];
    char value[INI_MAX_LINE];
} IniEntry;

typedef struct {
    IniEntry entries[INI_MAX_ENTRIES];
    int count;
    char error[INI_MAX_LINE];
} IniConfig;

/* Callback type for ini_parse_file */
typedef int (*ini_handler)(void* user, const char* section,
                           const char* name, const char* value);

/* Parse an INI file, calling handler for each name=value pair */
int ini_parse_file(const char* filename, ini_handler handler, void* user);

/* Parse an INI string buffer */
int ini_parse_string(const char* buf, ini_handler handler, void* user);

/* High-level API: load entire config into IniConfig struct */
IniConfig* ini_load(const char* filename);

/* Get a value by section and name, returns NULL if not found */
const char* ini_get(const IniConfig* config, const char* section, const char* name);

/* Get a value as integer, returns default_val if not found */
int ini_get_int(const IniConfig* config, const char* section,
                const char* name, int default_val);

/* Get a value as boolean (true/yes/1 = 1, false/no/0 = 0) */
int ini_get_bool(const IniConfig* config, const char* section,
                 const char* name, int default_val);

/* Free config memory */
void ini_free(IniConfig* config);

#endif /* INI_PARSER_H */
