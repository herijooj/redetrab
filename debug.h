// debug.h
#ifndef DEBUG_H
#define DEBUG_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

// Debug levels
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

// Forward declarations
struct Packet;
struct TransferStats {
    size_t total_expected;
    size_t total_received;
    size_t packets_processed;
    uint8_t last_sequence;
    int had_errors;
};

// Export debug level
extern int debug_level;

// Debug macros
void debug_print(int level, const char *fmt, ...);

#define DBG_ERROR(fmt, ...) \
    debug_print(DBG_LEVEL_ERROR, RED "[ERROR] " fmt RESET, ##__VA_ARGS__)

#define DBG_WARN(fmt, ...) \
    debug_print(DBG_LEVEL_WARN, YELLOW "[WARN] " fmt RESET, ##__VA_ARGS__)

#define DBG_INFO(fmt, ...) \
    debug_print(DBG_LEVEL_INFO, GREEN "[INFO] " fmt RESET, ##__VA_ARGS__)

#define DBG_TRACE(fmt, ...) \
    debug_print(DBG_LEVEL_TRACE, BLUE "[TRACE] " fmt RESET, ##__VA_ARGS__)

// Function declarations
void debug_init(void);
void debug_hex_dump(const char *prefix, const void *data, size_t size);
void debug_packet(const char *prefix, const struct Packet *packet);
void print_transfer_summary(const struct TransferStats *stats);

// Rename transfer-related function declarations
void transfer_init_stats(struct TransferStats *stats, size_t expected_size);
void transfer_update_stats(struct TransferStats *stats, size_t bytes, uint8_t seq);

#endif // DEBUG_H
