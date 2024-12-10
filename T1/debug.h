// debug.h
#ifndef DEBUG_H
#define DEBUG_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
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
    uint64_t total_expected;    
    uint64_t total_received;    
    uint64_t packets_processed; 
    uint16_t last_sequence;     
    uint16_t expected_seq;      
    uint32_t wrap_count;        // Track number of sequence wraps
    uint64_t total_sequences;   // Track total sequence count across wraps
    int had_errors;
    uint32_t retransmissions;   // Track number of retransmissions
    uint32_t duplicate_packets; // Track duplicate packets received
    uint32_t crc_errors;       // Track CRC errors
    uint32_t sequence_errors;  // Track sequence errors

    // Add more detailed error tracking
    struct {
        uint32_t consecutive_crc_errors;
        uint32_t consecutive_sequence_errors;
        uint64_t last_error_time;      // Timestamp of last error
        uint8_t last_valid_crc;        // Last valid CRC received
        uint8_t last_computed_crc;     // Last computed CRC
        uint8_t last_error_sequence;   // Sequence number when error occurred
        size_t last_error_packet_size;  // Size of packet when error occurred
        uint8_t error_packet_buffer[67]; // Buffer to store problematic packet
        uint8_t initial_sequence;     // Track initial sequence number
        uint8_t last_valid_sequence;  // Last successfully validated sequence
    } error_details;
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

// Add error log file handling
void debug_init_error_log(const char *role);
void debug_log_to_file(const char *fmt, ...);

#define ERROR_LOG_CLIENT "client_errors.log"
#define ERROR_LOG_SERVER "server_errors.log"

// Function declarations
void debug_init(void);
void debug_hex_dump(const char *prefix, const void *data, size_t size);
void debug_packet(const char *prefix, const struct Packet *packet);
void print_transfer_summary(const struct TransferStats *stats);

// Transfer-related functions
void transfer_init_stats(struct TransferStats *stats, size_t expected_size);
void transfer_update_stats(struct TransferStats *stats, size_t bytes, uint8_t seq);
void transfer_handle_wrap(struct TransferStats *stats);
void transfer_record_error(struct TransferStats *stats, int error_type);
bool transfer_is_duplicate(const struct TransferStats *stats, uint8_t seq);

// Add new debug functions
void debug_packet_validation(const struct Packet *packet, uint8_t computed_crc);
void debug_transfer_progress(const struct TransferStats *stats, const struct Packet *packet);
void debug_sequence_error(const struct TransferStats *stats, uint8_t received_seq);
void debug_retransmission(const struct TransferStats *stats, uint8_t seq, int attempt);

#endif // DEBUG_H
