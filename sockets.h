#ifndef SOCKETS_H
#define SOCKETS_H

// Remove duplicate includes
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

#define PACKET_SIZE 64
#define MAX_DATA_SIZE 1024  // Move this before Packet struct
#define START_MARKER 0xAA
#define TIMEOUT_SEC 5

// Add protocol identifier and node type
#define PROTO_MARKER 0x42  // Protocol identifier
#define NODE_SERVER  0x01
#define NODE_CLIENT  0x02

// Add these mask definitions
#define TYPE_MASK  0x1F    // 5-bit mask for packet type
#define SEQ_MASK   0x1F    // 5-bit mask for sequence number
#define LEN_MASK   0x3F    // 6-bit mask for length

// Add debug flags
#define DBG_PACKETS 1      // Set to 1 to enable detailed packet debugging
#define EXTENDED_VALIDATION 1  // Set to 1 to enable additional validation checks

// Define struct Packet (not typedef) for consistency with debug.h
struct Packet {
    uint8_t start_marker;    // 8 bits
    uint8_t proto_marker;    // Protocol identifier
    uint8_t node_type;      // Source node type
    uint8_t length;         // 6 bits (masked)
    uint8_t sequence;       // 5 bits (masked)
    uint8_t type;          // 5 bits (masked)
    uint8_t crc;           // 8 bits
    char data[MAX_DATA_SIZE];
};

typedef struct Packet Packet;  // Add typedef after struct definition

#include "debug.h"

// ...rest of existing code...

#define MAX_RETRIES 3
#define RETRY_DELAY_MS 100
#define SOCKET_TIMEOUT_MS 1000

// Remove the old DEBUG macro

// Packet types (according to codigos.md)
#define PKT_ACK       0x03  // 00011 Ack
#define PKT_BACKUP    0x04  // 00100 Backup
#define PKT_RESTORE   0x05  // 00101 Restore
#define PKT_VERIFY    0x06  // 00110 Verify
#define PKT_NACK      0x01  // 00001 Nack
#define PKT_OK        0x02  // 00010 Ok
#define PKT_SIZE      0x0F  // 01111 Tamanho
#define PKT_ERROR     0x1F  // 11111 Erro
#define PKT_DATA      0x10  // 10000 Dados
#define PKT_END_TX    0x11  // 10001 Fim TX Dados
#define PKT_OK_SIZE   0x0E  // 01110 OK + Tam
#define PKT_OK_CHSUM  0x0D  // 01101 OK + Checksum

// Error codes
#define ERR_NO_ACCESS 1  // Sem Acesso
#define ERR_NO_SPACE  2  // Sem Espaço
#define ERR_NOT_FOUND 3  // Não Encontrado
#define ERR_TIMEOUT    4  // Timeout
#define ERR_SEQUENCE   5  // Wrong sequence
#define ERR_CRC        6  // CRC error

// Function to calculate checksum
unsigned short checksum(void *b, int len);

// Function to create a raw socket
int create_raw_socket();

// Function to create a raw socket with a specified network interface
int cria_raw_socket(char *nome_interface_rede);

// Global variables for interface configuration
// extern int g_ifindex;
// extern unsigned char g_if_hwaddr[ETH_ALEN];
// extern struct sockaddr_ll g_socket_addr;

// Function prototypes - fix duplicates and add sockaddr_ll
uint8_t calculate_crc(Packet *packet);
int send_packet(int socket, Packet *packet, struct sockaddr_ll *addr);
int receive_packet(int socket, Packet *packet, struct sockaddr_ll *addr, int local_node_type);
void send_ack(int socket, struct sockaddr_ll *addr, uint8_t type);
void send_error(int socket, struct sockaddr_ll *addr, uint8_t error_code);
int set_socket_timeout(int socket, int timeout_ms);
int wait_for_ack(int socket, Packet *packet, struct sockaddr_ll *addr, uint8_t expected_type, int local_node_type);
int get_interface_info(int socket, char *interface, struct sockaddr_ll *addr);

#endif // SOCKETS_H

