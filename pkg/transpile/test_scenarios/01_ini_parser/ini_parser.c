/*
 * ini_parser.c - Simple INI file parser implementation
 * Inspired by inih (https://github.com/benhoyt/inih)
 */
#include "ini_parser.h"

/* Strip whitespace from both ends of a string in-place */
static char* strip(char* s) {
    char* end;

    /* Skip leading whitespace */
    while (isspace((unsigned char)*s))
        s++;

    if (*s == '\0')
        return s;

    /* Trim trailing whitespace */
    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end))
        end--;

    end[1] = '\0';
    return s;
}

/* Find the first occurrence of c in s, or return NULL */
static char* find_char(const char* s, char c) {
    while (*s) {
        if (*s == c)
            return (char*)s;
        s++;
    }
    return NULL;
}

/* Parse a single line: detect section headers, key=value pairs, comments */
static int parse_line(const char* line, char* section,
                      char* name, char* value) {
    char* start;
    char* end;
    char* eq;
    char temp[INI_MAX_LINE];

    strncpy(temp, line, INI_MAX_LINE - 1);
    temp[INI_MAX_LINE - 1] = '\0';

    start = strip(temp);

    /* Empty or comment line */
    if (*start == '\0' || *start == ';' || *start == '#')
        return 0;

    /* Section header */
    if (*start == '[') {
        end = find_char(start + 1, ']');
        if (end) {
            *end = '\0';
            strncpy(section, start + 1, INI_MAX_SECTION - 1);
            section[INI_MAX_SECTION - 1] = '\0';
            return 0;
        }
        return -1; /* Malformed section */
    }

    /* Key = value pair */
    eq = find_char(start, '=');
    if (!eq)
        eq = find_char(start, ':');

    if (eq) {
        *eq = '\0';
        strncpy(name, strip(start), INI_MAX_NAME - 1);
        name[INI_MAX_NAME - 1] = '\0';

        strncpy(value, strip(eq + 1), INI_MAX_LINE - 1);
        value[INI_MAX_LINE - 1] = '\0';

        /* Strip inline comments */
        end = find_char(value, ';');
        if (!end)
            end = find_char(value, '#');
        if (end) {
            /* Only treat as comment if preceded by whitespace */
            if (end > value && isspace((unsigned char)*(end - 1))) {
                *end = '\0';
                /* Re-strip trailing whitespace */
                char* v = value + strlen(value) - 1;
                while (v > value && isspace((unsigned char)*v))
                    *v-- = '\0';
            }
        }

        return 1; /* Found key=value */
    }

    return -1; /* Malformed line */
}

int ini_parse_string(const char* buf, ini_handler handler, void* user) {
    char section[INI_MAX_SECTION] = "";
    char name[INI_MAX_NAME];
    char value[INI_MAX_LINE];
    char line[INI_MAX_LINE];
    int lineno = 0;
    int error = 0;
    const char* p = buf;
    const char* nl;
    size_t len;

    while (*p) {
        nl = strchr(p, '\n');
        if (nl) {
            len = (size_t)(nl - p);
            if (len >= INI_MAX_LINE)
                len = INI_MAX_LINE - 1;
            memcpy(line, p, len);
            line[len] = '\0';
            p = nl + 1;
        } else {
            strncpy(line, p, INI_MAX_LINE - 1);
            line[INI_MAX_LINE - 1] = '\0';
            p += strlen(p);
        }

        /* Remove carriage return */
        len = strlen(line);
        if (len > 0 && line[len - 1] == '\r')
            line[len - 1] = '\0';

        lineno++;
        int result = parse_line(line, section, name, value);

        if (result < 0) {
            error = lineno;
            break;
        }

        if (result == 1) {
            if (handler && !handler(user, section, name, value)) {
                error = lineno;
                break;
            }
        }
    }

    return error;
}

int ini_parse_file(const char* filename, ini_handler handler, void* user) {
    FILE* fp;
    long size;
    char* buf;
    int result;

    fp = fopen(filename, "r");
    if (!fp)
        return -1;

    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (size <= 0) {
        fclose(fp);
        return 0;
    }

    buf = (char*)malloc((size_t)size + 1);
    if (!buf) {
        fclose(fp);
        return -2;
    }

    size_t nread = fread(buf, 1, (size_t)size, fp);
    buf[nread] = '\0';
    fclose(fp);

    result = ini_parse_string(buf, handler, user);
    free(buf);

    return result;
}

/* Internal handler for ini_load */
static int load_handler(void* user, const char* section,
                        const char* name, const char* value) {
    IniConfig* config = (IniConfig*)user;

    if (config->count >= INI_MAX_ENTRIES)
        return 0; /* Stop parsing */

    IniEntry* entry = &config->entries[config->count];
    strncpy(entry->section, section, INI_MAX_SECTION - 1);
    entry->section[INI_MAX_SECTION - 1] = '\0';
    strncpy(entry->name, name, INI_MAX_NAME - 1);
    entry->name[INI_MAX_NAME - 1] = '\0';
    strncpy(entry->value, value, INI_MAX_LINE - 1);
    entry->value[INI_MAX_LINE - 1] = '\0';
    config->count++;

    return 1;
}

IniConfig* ini_load(const char* filename) {
    IniConfig* config = (IniConfig*)calloc(1, sizeof(IniConfig));
    if (!config)
        return NULL;

    int err = ini_parse_file(filename, load_handler, config);
    if (err != 0) {
        snprintf(config->error, INI_MAX_LINE, "parse error at line %d", err);
    }

    return config;
}

const char* ini_get(const IniConfig* config, const char* section,
                    const char* name) {
    if (!config)
        return NULL;

    for (int i = 0; i < config->count; i++) {
        if (strcmp(config->entries[i].section, section) == 0 &&
            strcmp(config->entries[i].name, name) == 0) {
            return config->entries[i].value;
        }
    }

    return NULL;
}

int ini_get_int(const IniConfig* config, const char* section,
                const char* name, int default_val) {
    const char* val = ini_get(config, section, name);
    if (!val)
        return default_val;

    char* endptr;
    long result = strtol(val, &endptr, 10);
    if (endptr == val)
        return default_val;

    return (int)result;
}

int ini_get_bool(const IniConfig* config, const char* section,
                 const char* name, int default_val) {
    const char* val = ini_get(config, section, name);
    if (!val)
        return default_val;

    if (strcmp(val, "true") == 0 || strcmp(val, "yes") == 0 ||
        strcmp(val, "1") == 0 || strcmp(val, "on") == 0)
        return 1;

    if (strcmp(val, "false") == 0 || strcmp(val, "no") == 0 ||
        strcmp(val, "0") == 0 || strcmp(val, "off") == 0)
        return 0;

    return default_val;
}

void ini_free(IniConfig* config) {
    free(config);
}
