#include "sockets.h"
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <stdlib.h>
#include <stdio.h>

// Initialize global variables
int g_ifindex = 0;
unsigned char g_if_hwaddr[ETH_ALEN];
struct sockaddr_ll g_socket_addr = {0};

int get_interface_info(int socket, char *interface, struct sockaddr_ll *addr) {
    struct ifreq if_idx;
    struct ifreq if_mac;
    
    memset(&if_idx, 0, sizeof(if_idx));
    strncpy(if_idx.ifr_name, interface, IFNAMSIZ-1);
    if (ioctl(socket, SIOCGIFINDEX, &if_idx) < 0) {
        perror("SIOCGIFINDEX");
        return -1;
    }
    g_ifindex = if_idx.ifr_ifindex;

    memset(&if_mac, 0, sizeof(if_mac));
    strncpy(if_mac.ifr_name, interface, IFNAMSIZ-1);
    if (ioctl(socket, SIOCGIFHWADDR, &if_mac) < 0) {
        perror("SIOCGIFHWADDR");
        return -1;
    }
    memcpy(g_if_hwaddr, if_mac.ifr_hwaddr.sa_data, ETH_ALEN);

    // Initialize global socket address
    memset(&g_socket_addr, 0, sizeof(g_socket_addr));
    g_socket_addr.sll_family = AF_PACKET;
    g_socket_addr.sll_protocol = htons(ETH_P_ALL);
    g_socket_addr.sll_ifindex = g_ifindex;
    g_socket_addr.sll_halen = ETH_ALEN;
    memcpy(g_socket_addr.sll_addr, g_if_hwaddr, ETH_ALEN);

    if (addr) {
        memcpy(addr, &g_socket_addr, sizeof(*addr));
    }
    
    return 0;
}

int cria_raw_socket(char *nome_interface_rede)
{
    debug_print("Creating raw socket on interface %s\n", nome_interface_rede);
    int soquete = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (soquete == -1)
    {
        fprintf(stderr, "Erro ao criar socket: Verifique se voce eh root!\n");
        exit(-1);
    }

    struct sockaddr_ll endereco;
    if (get_interface_info(soquete, nome_interface_rede, &endereco) < 0) {
        exit(-1);
    }

    if (bind(soquete, (struct sockaddr *)&endereco, sizeof(endereco)) == -1)
    {
        fprintf(stderr, "Erro ao fazer bind no socket\n");
        exit(-1);
    }

    struct packet_mreq mr = {0};
    mr.mr_ifindex = g_ifindex;
    mr.mr_type = PACKET_MR_PROMISC;

    // Não joga fora o que identifica como lixo: Modo promíscuo
    if (setsockopt(soquete, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) == -1)
    {
        fprintf(stderr, "Erro ao fazer setsockopt: "
                        "Verifique se a interface de rede foi especificada corretamente.\n");
        exit(-1);
    }

    return soquete;
}

int set_socket_timeout(int socket, int timeout_ms) {
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    
    if (setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        debug_print("Failed to set socket timeout\n");
        return -1;
    }
    return 0;
}

uint8_t calculate_crc(Packet *packet) {
    uint8_t crc = 0;
    crc ^= packet->start_marker;
    crc ^= packet->length;
    crc ^= packet->sequence;
    crc ^= packet->type;
    for (int i = 0; i < (packet->length & 0x3F); i++) {
        crc ^= packet->data[i];
    }
    return crc;
}

int send_packet(int socket, Packet *packet, struct sockaddr_ll *addr) {
    debug_print("Sending packet type: 0x%02x, seq: %d, len: %d\n", 
                packet->type, packet->sequence, packet->length);
    packet->start_marker = START_MARKER;
    packet->crc = calculate_crc(packet);

    // Ensure addr is properly initialized
    if (!addr->sll_ifindex) {
        debug_print("Error: socket address not properly initialized\n");
        return -1;
    }

    ssize_t sent = sendto(socket, packet, sizeof(Packet), 0, 
                         (struct sockaddr *)addr, sizeof(*addr));
    if (sent < 0) {
        debug_print("sendto failed: %s\n", strerror(errno));
        return -1;
    }
    
    debug_print("Successfully sent %zd bytes\n", sent);
    return sent;
}

int receive_packet(int socket, Packet *packet) {
    struct sockaddr_ll addr;
    socklen_t addr_len = sizeof(addr);
    
    ssize_t received = recvfrom(socket, packet, sizeof(Packet), 0,
                               (struct sockaddr *)&addr, &addr_len);
    debug_print("Received %zd bytes\n", received);
    if (received <= 0) return -1;
    
    debug_print("Packet type: 0x%02x, seq: %d, len: %d\n", 
                packet->type, packet->sequence, packet->length);

    // Ensure sll_halen and sll_addr are set
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_halen = ETH_ALEN;
    if (addr.sll_pkttype == PACKET_OUTGOING) {
        // Ignore outgoing packets
        return -1;
    }

    // Store sender's address in global socket address
    memcpy(&g_socket_addr, &addr, sizeof(g_socket_addr));

    if (packet->start_marker != START_MARKER) return -1;
    if (packet->crc != calculate_crc(packet)) return -1;
    
    return received;
}

int wait_for_ack(int socket, Packet *packet, uint8_t expected_type) {
    int retries = 0;
    while (retries < MAX_RETRIES) {
        if (receive_packet(socket, packet) > 0) {
            if ((packet->type & 0x1F) == expected_type) {
                return 0;
            }
            if ((packet->type & 0x1F) == PKT_NACK) {
                debug_print("Received NACK\n");
                return -1;
            }
        }
        retries++;
        debug_print("No ACK received, retry %d\n", retries);
        usleep(RETRY_DELAY_MS * 1000);
    }
    return -1;
}

void send_ack(int socket, struct sockaddr_ll *addr, uint8_t type) {
    Packet ack = {0};
    ack.type = PKT_ACK | type;
    send_packet(socket, &ack, addr);
}

void send_error(int socket, struct sockaddr_ll *addr, uint8_t error_code) {
    Packet error = {0};
    error.type = PKT_ERROR;
    error.data[0] = error_code;
    error.length = 1;
    send_packet(socket, &error, addr);
}