// debug.c  
#include "debug.h"
#include <time.h>
#include "sockets.h"
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

// Add at top after includes
static FILE *error_log_file = NULL;

int debug_level = DBG_LEVEL_INFO;  // Default level

static struct timeval start_time;

void debug_init(void) {
    char *level = getenv("DEBUG_LEVEL");
    if (level) {
        debug_level = atoi(level);
    }
    gettimeofday(&start_time, NULL);
}

void debug_init_error_log(const char *role) {
    const char *filename = (strcmp(role, "server") == 0) ? ERROR_LOG_SERVER : ERROR_LOG_CLIENT;
    error_log_file = fopen(filename, "a");
    if (error_log_file) {
        time_t now = time(NULL);
        fprintf(error_log_file, "\n=== New session started at %s", ctime(&now));
        fflush(error_log_file);
    }
}

void debug_print(int level, const char *fmt, ...) {
    if (level > debug_level) return;

    struct timeval now;
    gettimeofday(&now, NULL);
    long elapsed = (now.tv_sec - start_time.tv_sec) * 1000 +
                  (now.tv_usec - start_time.tv_usec) / 1000;

    fprintf(stderr, "[%.3f] ", elapsed/1000.0);

    va_list args;
    va_start(args, fmt);

    // Print to stderr as before
    vfprintf(stderr, fmt, args);
    
    // Also log errors and warnings to file
    if (level <= DBG_LEVEL_WARN && error_log_file) {
        va_end(args);
        va_start(args, fmt);
        vfprintf(error_log_file, fmt, args);
        fflush(error_log_file);
    }
    
    va_end(args);
    
    // Force flush on errors and warnings
    if (level <= DBG_LEVEL_WARN) {
        fflush(stderr);
    }
}

void debug_log_to_file(const char *fmt, ...) {
    if (!error_log_file) return;

    struct timeval now;
    gettimeofday(&now, NULL);
    
    // Write timestamp
    fprintf(error_log_file, "[%ld.%03ld] ", now.tv_sec, now.tv_usec / 1000);
    
    // Write formatted message
    va_list args;
    va_start(args, fmt);
    vfprintf(error_log_file, fmt, args);
    va_end(args);
    
    fflush(error_log_file);
}

void debug_hex_dump(const char *prefix, const void *data, size_t size) {
    if (debug_level < DBG_LEVEL_TRACE) return;

    const unsigned char *p = data;
    fprintf(stderr, "%s", prefix);
    for (size_t i = 0; i < size; i++) {
        if (i > 0 && i % 16 == 0)
            fprintf(stderr, "\n%s", prefix);
        fprintf(stderr, "%02x ", p[i]);
    }
    fprintf(stderr, "\n");
}

// Add a helper function to get packet type as string
const char* packet_type_to_string(uint8_t type) {
    switch (type) {
        case PKT_NACK:      return "NACK";
        case PKT_OK:        return "OK";
        case PKT_BACKUP:    return "BACKUP";
        case PKT_OK_CHSUM:  return "OK_CHSUM";
        case PKT_OK_SIZE:   return "OK_SIZE";
        case PKT_SIZE:      return "SIZE";
        case PKT_DATA:      return "DATA";
        case PKT_END_TX:    return "END_TX";
        case PKT_ERROR:     return "ERROR";
        case PKT_RESTORE:   return "RESTORE";
        case PKT_VERIFY:    return "VERIFY";
        case PKT_ACK:       return "ACK";
        default:            return "UNKNOWN";
    }
}

void debug_packet(const char *prefix, const struct Packet *packet) {
    if (debug_level < DBG_LEVEL_INFO) return;
    
    uint8_t type = GET_TYPE(packet->size_seq_type);
    uint8_t seq = GET_SEQUENCE(packet->size_seq_type);
    uint8_t len = GET_SIZE(packet->size_seq_type);
    
    const char *type_str = packet_type_to_string(type);
    
    DBG_INFO("%s: type=%s seq=%u len=%u crc=0x%02x\n", prefix, type_str, seq, len, packet->crc);
    
    if (debug_level >= DBG_LEVEL_TRACE) {
        debug_hex_dump("  Data: ", packet->data, len);
        debug_hex_dump("  Full Packet: ", packet, sizeof(Packet));
    }
}

void debug_packet_validation(const struct Packet *packet, uint8_t computed_crc) {
    if (debug_level < DBG_LEVEL_INFO) return;
    
    if (packet->crc != computed_crc) {
        DBG_ERROR("CRC error details:\n");
        DBG_ERROR("  Computed CRC: 0x%02x\n", computed_crc);
        DBG_ERROR("  Received CRC: 0x%02x\n", packet->crc);
        DBG_ERROR("  Sequence: %u\n", GET_SEQUENCE(packet->size_seq_type));
        DBG_ERROR("  Type: %s\n", packet_type_to_string(GET_TYPE(packet->size_seq_type)));
        DBG_ERROR("  Size field: %u\n", GET_SIZE(packet->size_seq_type));
        debug_hex_dump("  Raw packet: ", packet, sizeof(Packet));
    }
}

void debug_transfer_progress(const struct TransferStats *stats, const struct Packet *packet) {
    float progress = (float)stats->total_received / stats->total_expected * 100;
    DBG_INFO("Progress: %.1f%% [%lu/%lu] Seq=%u Wrap=%u\n",
             progress, stats->total_received, stats->total_expected,
             stats->last_sequence, stats->wrap_count);
}

void debug_sequence_error(const struct TransferStats *stats, uint8_t received_seq) {
    DBG_ERROR("Seq err: exp=%u got=%u last=%u (errs=%u)\n",
             stats->expected_seq, received_seq, 
             stats->last_sequence, stats->sequence_errors);
}

void debug_retransmission(const struct TransferStats *stats, uint8_t seq, int attempt) {
    DBG_WARN("Retry: seq=%u try=%d/%d (total=%u)\n",
             seq, attempt, MAX_RETRIES, stats->retransmissions);
}

void transfer_init_stats(struct TransferStats *stats, size_t expected_size) {
    memset(stats, 0, sizeof(struct TransferStats));
    stats->total_expected = expected_size;
    stats->expected_seq = 0;  // Explicitly initialize expected sequence
    stats->last_sequence = 0; // Explicitly initialize last sequence
}

void transfer_handle_wrap(struct TransferStats *stats) {
    stats->wrap_count++;
    stats->total_sequences = (uint64_t)stats->wrap_count * (SEQ_NUM_MAX + 1) + stats->last_sequence;
    DBG_INFO("Sequence wrapped around (count: %u, total sequences: %lu)\n", 
             stats->wrap_count, stats->total_sequences);
}

void transfer_update_stats(struct TransferStats *stats, size_t bytes, uint8_t seq) {
    // Don't update total_received here - let the caller handle it
    stats->packets_processed++;
    
    // Check for wrap-around
    if (seq < stats->last_sequence && stats->last_sequence > SEQ_NUM_MAX/2) {
        transfer_handle_wrap(stats);
    }
    
    stats->last_sequence = seq;
    stats->expected_seq = (seq + 1) & SEQ_NUM_MAX;
}

void print_transfer_summary(const struct TransferStats *stats) {
    DBG_INFO("Transfer Summary:\n");
    DBG_INFO("  Expected: %zu bytes\n", stats->total_expected);
    DBG_INFO("  Received: %zu bytes\n", stats->total_received);
    DBG_INFO("  Packets:  %zu\n", stats->packets_processed);
    DBG_INFO("  Status:   %s\n", stats->had_errors ? "Had errors" : "Clean");

    if (stats->total_expected != stats->total_received) {
        DBG_ERROR("Transfer incomplete! Missing %zd bytes\n",
                  stats->total_expected - stats->total_received);
    }
    DBG_INFO("  CRC Errors: %u\n", stats->crc_errors);
    DBG_INFO("  Sequence Errors: %u\n", stats->sequence_errors);
    DBG_INFO("  Retransmissions: %u\n", stats->retransmissions);
    DBG_INFO("  Duplicate Packets: %u\n", stats->duplicate_packets);
    
    if (stats->error_details.consecutive_crc_errors > 0) {
        DBG_ERROR("Last CRC error details:\n");
        DBG_ERROR("  Expected: 0x%02x\n", stats->error_details.last_computed_crc);
        DBG_ERROR("  Received: 0x%02x\n", stats->error_details.last_valid_crc);
        DBG_ERROR("  At sequence: %u\n", stats->error_details.last_error_sequence);
    }
}

bool transfer_is_duplicate(const struct TransferStats *stats, uint8_t seq)
{
    if (seq == stats->last_sequence) {
        DBG_WARN("Duplicate packet received: seq=%u\n", seq);
        return true;
    }
    return false;
}
