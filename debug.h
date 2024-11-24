#ifndef DEBUG_H
#define DEBUG_H

#include <stdio.h>
#include <time.h>

// Debug level values
enum {
    DBG_LEVEL_NONE  = 0,
    DBG_LEVEL_ERROR = 1,
    DBG_LEVEL_WARN  = 2,
    DBG_LEVEL_INFO  = 3,
    DBG_LEVEL_TRACE = 4
};

// Colors
#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"
#define YELLOW  "\x1b[33m"
#define BLUE    "\x1b[34m"
#define RESET   "\x1b[0m"

// Set debug level (can be changed through environment variable DEBUG_LEVEL)
extern int debug_level;

// Forward declaration of Packet structure
struct Packet;

// Debug macros
#define DBG_ERROR(fmt, ...) \
    debug_print(DBG_LEVEL_ERROR, RED "[ERROR] " fmt RESET, ##__VA_ARGS__)

#define DBG_WARN(fmt, ...) \
    debug_print(DBG_LEVEL_WARN, YELLOW "[WARN] " fmt RESET, ##__VA_ARGS__)

#define DBG_INFO(fmt, ...) \
    debug_print(DBG_LEVEL_INFO, GREEN "[INFO] " fmt RESET, ##__VA_ARGS__)

#define DBG_TRACE(fmt, ...) \
    debug_print(DBG_LEVEL_TRACE, BLUE "[TRACE] " fmt RESET, ##__VA_ARGS__)

void debug_init(void);
void debug_print(int level, const char *fmt, ...);
void debug_hex_dump(const char *prefix, const void *data, size_t size);
void debug_packet(const char *prefix, const struct Packet *packet);

#endif // DEBUG_H