// sockets.h
#ifndef SOCKETS_H
#define SOCKETS_H

#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <limits.h>
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include "debug.h"

#define MAX_DATA_SIZE 63  // Adjusted to 6-bit length field

#define START_MARKER 0xAA

// Packet types
typedef enum {
    PKT_NACK      = 0x01,  // Negative acknowledgment
    PKT_OK        = 0x02,  // OK
    PKT_ACK       = 0x03,  // Acknowledgment
    PKT_BACKUP    = 0x04,  // Backup request
    PKT_RESTORE   = 0x05,  // Restore request
    PKT_VERIFY    = 0x06,  // Verify request
    PKT_OK_CHSUM  = 0x0D,  // OK + Checksum
    PKT_OK_SIZE   = 0x0E,  // OK + Size
    PKT_SIZE      = 0x0F,  // Size info
    PKT_DATA      = 0x10,  // Data packet
    PKT_END_TX    = 0x11,  // End transmission
    PKT_ERROR     = 0x1F   // Error
} PacketType;

// Error codes
typedef enum {
    ERR_NO_ACCESS = 1,  // Access denied
    ERR_NO_SPACE  = 2,  // No space
    ERR_NOT_FOUND = 3,  // File not found
    ERR_TIMEOUT   = 4,  // Timeout
    ERR_SEQUENCE  = 5,  // Wrong sequence
    ERR_CRC       = 6   // CRC error
} ErrorCode;

// Protocol constants
typedef enum {
    SOCKET_TIMEOUT_MS = 5000,
    TIMEOUT_SEC = 5,
    MAX_RETRIES = 5,
    RETRY_DELAY_MS = 500,
    MAX_CONSECUTIVE_CRC_ERRORS = 3,
    CRC_ERROR_BACKOFF_MS = 100,
    CRC_RETRANSMIT_DELAY_MS = 50,
    CRC_VALIDATION_ATTEMPTS = 3,
    CRC_MAX_ERRORS = 3
} ProtocolConstants;

// Field masks and limits
typedef enum {
    SIZE_MASK = 0xFC00,
    SEQ_FIELD_MASK = 0x03E0,
    TYPE_MASK = 0x001F,
    SIZE_SHIFT = 10,
    SEQ_SHIFT = 5,
    TYPE_SHIFT = 0,
    SIZEFIELD_MAX = 0x3F,
    SEQ_NUM_MAX = 0x1F,
    TYPE_MAX = 0x1F
} FieldMasks;

// Packet validation macros
#define VALIDATE_START_MARKER(marker) ((marker) == START_MARKER)
#define VALIDATE_CRC(computed, received) ((computed) == (received))

// Masks for the fields in size_seq_type
#define SIZE_MASK       0xFC00  // Bits 15-10 (6 bits)
#define SIZE_SHIFT      10

#define SEQ_FIELD_MASK  0x03E0  // Bits 9-5 (5 bits)
#define SEQ_SHIFT       5

#define TYPE_MASK       0x001F  // Bits 4-0 (5 bits)
#define TYPE_SHIFT      0

// Maximum values for fields
#define SIZEFIELD_MAX        0x3F    // 6 bits
#define SEQ_NUM_MAX     0x1F    // 5 bits
#define TYPE_MAX        0x1F    // 5 bits

// Macros for setting fields
#define SET_SIZE(sst, size) \
    ((sst) = ((sst) & ~SIZE_MASK) | (((size) & SIZEFIELD_MAX) << SIZE_SHIFT))

#define SET_SEQUENCE(sst, seq) \
    ((sst) = ((sst) & ~SEQ_FIELD_MASK) | (((seq) & SEQ_NUM_MAX) << SEQ_SHIFT))

#define SET_TYPE(sst, type) \
    ((sst) = ((sst) & ~TYPE_MASK) | (((type) & TYPE_MAX) << TYPE_SHIFT))

// Macros for getting fields
#define GET_SIZE(sst)      (((sst) & SIZE_MASK) >> SIZE_SHIFT)
#define GET_SEQUENCE(sst)  (((sst) & SEQ_FIELD_MASK) >> SEQ_SHIFT)
#define GET_TYPE(sst)      (((sst) & TYPE_MASK) >> TYPE_SHIFT)

#define SEQ_MAX 0x1F // 5 bits

// Update sequence difference macro
#define SEQ_DIFF(a, b) (((a) - (b)) & SEQ_NUM_MAX)

#define SEQ_LT(a, b)   (SEQ_DIFF(a, b) > (SEQ_NUM_MAX / 2))
#define SEQ_GT(a, b)   (SEQ_DIFF(b, a) > (SEQ_NUM_MAX / 2))
#define SEQ_LEQ(a, b)  (!SEQ_GT(a, b))
#define SEQ_GEQ(a, b)  (!SEQ_LT(a, b))

// Add validation macros
#define VALIDATE_SEQUENCE(seq) ((seq) <= SEQ_NUM_MAX)
#define VALIDATE_SIZE(size) ((size) <= MAX_DATA_SIZE)
#define VALIDATE_TYPE(type) ((type) <= TYPE_MAX)

#pragma pack(push, 1)
#define PAD_SIZE ((64 > (sizeof(uint8_t) + sizeof(uint16_t) + MAX_DATA_SIZE + sizeof(uint8_t))) ? (64 - sizeof(uint8_t) - sizeof(uint16_t) - MAX_DATA_SIZE - sizeof(uint8_t)) : 0)
struct Packet {
    uint8_t start_marker;     // 8 bits
    uint16_t size_seq_type;   // size (6 bits), sequence (5 bits), type (5 bits)
    char data[MAX_DATA_SIZE];
    uint8_t crc;              // 8 bits
    uint8_t padding[PAD_SIZE]; // Padding to reach 64 bytes
};
#pragma pack(pop)

#define MIN_PACKET_SIZE (sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint8_t)) // start_marker + size_seq_type + crc

typedef struct Packet Packet;

// Function declarations
uint8_t calculate_crc(Packet *packet);
int send_packet(int socket, Packet *packet, struct sockaddr_ll *addr, bool is_send);
ssize_t receive_packet(int socket, Packet *packet, struct sockaddr_ll *addr, bool is_send);
void send_ack(int socket, struct sockaddr_ll *addr, uint8_t type, bool is_send);
void send_error(int socket, struct sockaddr_ll *addr, uint8_t error_code, bool is_send);
int set_socket_timeout(int socket, int timeout_ms);
int wait_for_ack(int socket, Packet *packet, struct sockaddr_ll *addr, uint8_t expected_type);
int get_interface_info(int socket, char *interface, struct sockaddr_ll *addr);
int cria_raw_socket(char *nome_interface_rede);
int validate_packet(Packet *packet, bool is_send);
int validate_packet_fields(Packet *packet);
uint8_t calculate_crc_robust(const Packet *packet, bool is_send);
int validate_crc(const Packet *packet, bool is_send);  // Updated declaration

struct PacketStats {
    uint64_t total_bytes;       // Changed from size_t
    uint64_t packets_sent;      // Changed from size_t
    uint64_t packets_received;  // Changed from size_t
    uint64_t retries;           // Changed from size_t
};

void init_packet_stats(struct PacketStats *stats);
void update_packet_stats(struct PacketStats *stats, size_t bytes, int is_send);

#endif // SOCKETS_H
