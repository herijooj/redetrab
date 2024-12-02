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
#define PKT_NACK      0x01  // 00001 Negative acknowledgment
#define PKT_OK        0x02  // 00010 OK
#define PKT_BACKUP    0x04  // 00100 Backup request
#define PKT_OK_CHSUM  0x0D  // 01101 OK + Checksum
#define PKT_OK_SIZE   0x0E  // 01110 OK + Size
#define PKT_SIZE      0x0F  // 01111 Size info
#define PKT_DATA      0x10  // 10000 Data packet
#define PKT_END_TX    0x11  // 10001 End transmission
#define PKT_ERROR     0x1F  // 11111 Error
#define PKT_RESTORE   0x05  // Restore request
#define PKT_VERIFY    0x06  // Verify request
#define PKT_ACK       0x03  // Acknowledgment 

// Error codes
#define ERR_NO_ACCESS 1  // Sem Acesso
#define ERR_NO_SPACE  2  // Sem Espaço
#define ERR_NOT_FOUND 3  // Não Encontrado
#define ERR_TIMEOUT   4  // Timeout
#define ERR_SEQUENCE  5  // Wrong Sequence
#define ERR_CRC       6  // CRC Error

// Timeout and retry definitions
#define SOCKET_TIMEOUT_MS 5000  // 5 seconds
#define TIMEOUT_SEC 5           // 5 seconds
#define MAX_RETRIES 5
#define RETRY_DELAY_MS 500      // 500 milliseconds

// Masks and shifts
#define SIZE_MASK 0xFC00  // Bits 15-10 (6 bits)
#define SIZE_SHIFT 10

#define SEQ_MASK  0x03E0  // Bits 9-5 (5 bits)
#define SEQ_SHIFT 5

#define TYPE_MASK 0x001F  // Bits 4-0 (5 bits)
#define TYPE_SHIFT 0

#define GET_SIZE(sst) (((sst) & SIZE_MASK) >> SIZE_SHIFT)
#define GET_SEQUENCE(sst) (((sst) & SEQ_MASK) >> SEQ_SHIFT)
#define GET_TYPE(sst) (((sst) & TYPE_MASK) >> TYPE_SHIFT)

#define SET_SIZE(sst, size) \
    ((sst) = ((sst) & ~SIZE_MASK) | (((size) & 0x3F) << SIZE_SHIFT))

#define SET_SEQUENCE(sst, sequence) \
    ((sst) = ((sst) & ~SEQ_MASK) | (((sequence) & 0x1F) << SEQ_SHIFT))

#define SET_TYPE(sst, type) \
    ((sst) = ((sst) & ~TYPE_MASK) | (((type) & 0x1F) << TYPE_SHIFT))

#define SEQ_MAX 0x1F // 5 bits

// Update sequence difference macro
#define SEQ_DIFF(a, b) ((uint8_t)((a) - (b)) & SEQ_MAX)

// Update sequence comparison macros
#define SEQ_LT(a, b)   (SEQ_DIFF(a, b) > (SEQ_MAX / 2))
#define SEQ_GT(a, b)   (SEQ_DIFF(b, a) > (SEQ_MAX / 2))
#define SEQ_LEQ(a, b)  (!SEQ_GT(a, b))
#define SEQ_GEQ(a, b)  (!SEQ_LT(a, b))

#pragma pack(push, 1)
struct Packet {
    uint8_t start_marker;     // 8 bits
    uint16_t size_seq_type;   // size (6 bits), sequence (5 bits), type (5 bits)
    char data[MAX_DATA_SIZE];
    uint8_t crc;              // 8 bits
};
#pragma pack(pop)

typedef struct Packet Packet;

// Function declarations
uint8_t calculate_crc(Packet *packet);
int send_packet(int socket, Packet *packet, struct sockaddr_ll *addr);
int receive_packet(int socket, Packet *packet, struct sockaddr_ll *addr);
void send_ack(int socket, struct sockaddr_ll *addr, uint8_t type);
void send_error(int socket, struct sockaddr_ll *addr, uint8_t error_code);
int set_socket_timeout(int socket, int timeout_ms);
int wait_for_ack(int socket, Packet *packet, struct sockaddr_ll *addr, uint8_t expected_type);
int get_interface_info(int socket, char *interface, struct sockaddr_ll *addr);
int cria_raw_socket(char *nome_interface_rede);
int validate_packet(Packet *packet);

struct PacketStats {
    uint64_t total_bytes;       // Changed from size_t
    uint64_t packets_sent;      // Changed from size_t
    uint64_t packets_received;  // Changed from size_t
    uint64_t retries;           // Changed from size_t
};

void init_packet_stats(struct PacketStats *stats);
void update_packet_stats(struct PacketStats *stats, size_t bytes, int is_send);

#endif // SOCKETS_H
