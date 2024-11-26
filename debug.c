// Debug.c - Debugging utilities 

#include "debug.h"
#include "sockets.h"
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

int debug_level = DBG_LEVEL_INFO;  // Default level

static struct timeval start_time;

void debug_init(void) {
    char *level = getenv("DEBUG_LEVEL");
    if (level) {
        debug_level = atoi(level);
    }
    gettimeofday(&start_time, NULL);
}

void debug_print(int level, const char *fmt, ...) {
    if (level > debug_level) return;

    struct timeval now;
    gettimeofday(&now, NULL);
    long elapsed = (now.tv_sec - start_time.tv_sec) * 1000 +
                  (now.tv_usec - start_time.tv_usec) / 1000;

    fprintf(stderr, "[%ld.%03ld] ", elapsed/1000, elapsed%1000);
    
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
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

void debug_packet(const char *prefix, const struct Packet *packet) {
    if (debug_level < DBG_LEVEL_INFO) return;

    const char *type_str;
    switch (packet->type & TYPE_MASK) {
        case PKT_NACK:      type_str = "NACK"; break;
        case PKT_OK:        type_str = "OK"; break;
        case PKT_ACK:       type_str = "ACK"; break;
        case PKT_BACKUP:    type_str = "BACKUP"; break;
        case PKT_RESTORE:   type_str = "RESTORE"; break;
        case PKT_VERIFY:    type_str = "VERIFY"; break;
        case PKT_OK_CHSUM:  type_str = "OK_CHSUM"; break;
        case PKT_OK_SIZE:   type_str = "OK_SIZE"; break;
        case PKT_SIZE:      type_str = "SIZE"; break;
        case PKT_DATA:      type_str = "DATA"; break;
        case PKT_END_TX:    type_str = "END_TX"; break;
        case PKT_ERROR:     type_str = "ERROR"; break;
        default:            type_str = "UNKNOWN"; break;
    }

    DBG_INFO("%s: type=%s seq=%d len=%d\n", 
         prefix, type_str, packet->sequence, packet->length);    
    if (debug_level >= DBG_LEVEL_TRACE) {
        debug_hex_dump("  ", packet->data, packet->length);
    }
}

void init_packet_stats(struct PacketStats *stats) {
    memset(stats, 0, sizeof(struct PacketStats));
}

void update_packet_stats(struct PacketStats *stats, size_t bytes, int is_send) {
    stats->total_bytes += bytes;
    if (is_send) {
        stats->packets_sent++;
    } else {
        stats->packets_received++;
    }
}

void transfer_init_stats(struct TransferStats *stats, size_t expected_size) {
    memset(stats, 0, sizeof(struct TransferStats));
    stats->total_expected = expected_size;
}

void transfer_update_stats(struct TransferStats *stats, size_t bytes, uint8_t seq) {
    stats->total_received += bytes;
    stats->packets_processed++;
    
    // Check for sequence gaps
    if (stats->packets_processed > 1 && 
        ((seq & SEQ_MASK) != ((stats->last_sequence + 1) & SEQ_MASK))) {
        DBG_WARN("Sequence gap detected: last=%u, current=%u\n", 
                stats->last_sequence, seq);
        stats->had_errors = 1;
    }
    stats->last_sequence = seq;
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
}

// End of debug.c