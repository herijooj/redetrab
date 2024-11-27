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

// Masks
#define TYPE_MASK 0x1F  // 5 bits
#define SEQ_MASK 0x1F   // 5 bits
#define LEN_MASK 0x3F   // 6 bits

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

#pragma pack(push, 1)
struct Packet {
    uint8_t start_marker;   // 8 bits
    uint8_t length;         // 6 bits (masked)
    uint8_t sequence;       // 5 bits (masked)
    uint8_t type;           // 5 bits (masked)
    char data[MAX_DATA_SIZE];
    uint8_t crc;            // 8 bits
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
    size_t total_bytes;
    size_t packets_sent;
    size_t packets_received;
    size_t retries;
};

void init_packet_stats(struct PacketStats *stats);
void update_packet_stats(struct PacketStats *stats, size_t bytes, int is_send);

#endif // SOCKETS_H
