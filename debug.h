#ifndef DEBUG_H
#define DEBUG_H

#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <sys/types.h>

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

// Add file transfer statistics structure
struct TransferStats {
    size_t total_expected;   // Total expected bytes
    size_t total_received;   // Total bytes received/sent
    size_t packets_processed; // Number of packets processed
    size_t last_sequence;    // Last sequence number processed
    int had_errors;         // Error flag
    uint8_t expected_seq;
};

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

// Add function declarations
void init_transfer_stats(struct TransferStats *stats, size_t expected_size);
void update_transfer_stats(struct TransferStats *stats, size_t bytes, uint8_t seq);
void print_transfer_summary(const struct TransferStats *stats);

#endif // DEBUG_H