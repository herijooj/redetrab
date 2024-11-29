#include "sockets.h"
#include "debug.h"
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <stdlib.h>
#include <stdio.h>

int get_interface_info(int socket, char *interface, struct sockaddr_ll *addr) {
    struct ifreq if_idx;
    struct ifreq if_mac;

    memset(&if_idx, 0, sizeof(if_idx));
    strncpy(if_idx.ifr_name, interface, IFNAMSIZ - 1);
    if (ioctl(socket, SIOCGIFINDEX, &if_idx) < 0) {
        perror("SIOCGIFINDEX");
        return -1;
    }
    int ifindex = if_idx.ifr_ifindex;

    memset(&if_mac, 0, sizeof(if_mac));
    strncpy(if_mac.ifr_name, interface, IFNAMSIZ - 1);
    if (ioctl(socket, SIOCGIFHWADDR, &if_mac) < 0) {
        perror("SIOCGIFHWADDR");
        return -1;
    }

    // Initialize socket address
    memset(addr, 0, sizeof(struct sockaddr_ll));
    addr->sll_family = AF_PACKET;
    addr->sll_protocol = htons(ETH_P_ALL);
    addr->sll_ifindex = ifindex;
    addr->sll_halen = ETH_ALEN;
    memcpy(addr->sll_addr, if_mac.ifr_hwaddr.sa_data, ETH_ALEN);

    return 0;
}

int cria_raw_socket(char *nome_interface_rede) {
    DBG_INFO("Creating raw socket on interface %s\n", nome_interface_rede);
    int soquete = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (soquete == -1) {
        DBG_ERROR("Error creating socket: Root privileges required!\n");
        exit(-1);
    }

    struct sockaddr_ll endereco;
    if (get_interface_info(soquete, nome_interface_rede, &endereco) < 0) {
        exit(-1);
    }

    if (bind(soquete, (struct sockaddr *)&endereco, sizeof(endereco)) == -1) {
        fprintf(stderr, "Erro ao fazer bind no socket\n");
        exit(-1);
    }

    struct packet_mreq mr = {0};
    mr.mr_ifindex = endereco.sll_ifindex;
    mr.mr_type = PACKET_MR_PROMISC;

    // Enable promiscuous mode
    if (setsockopt(soquete, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) == -1) {
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
        DBG_ERROR("Failed to set socket timeout\n");
        return -1;
    }
    return 0;
}

uint8_t calculate_crc(Packet *packet) {
    uint8_t crc = 0;
    crc ^= packet->start_marker;
    crc ^= packet->length & LEN_MASK;
    crc ^= (packet->sequence >> 8) & 0xFF;  // Include high byte
    crc ^= packet->sequence & 0xFF;         // Include low byte
    crc ^= packet->type & TYPE_MASK;
    for (int i = 0; i < (packet->length & LEN_MASK); i++) {
        crc ^= packet->data[i];
    }
    return crc;
}

int validate_packet(Packet *packet) {
    // Check start marker
    if (packet->start_marker != START_MARKER) {
        DBG_WARN("Invalid start marker: 0x%02x\n", packet->start_marker);
        return -1;
    }
    // Validate length field
    size_t data_len = packet->length & LEN_MASK;
    if (data_len > MAX_DATA_SIZE) {
        DBG_WARN("Invalid length: %zu\n", data_len);
        return -1;
    }
    // Verify CRC
    uint8_t computed_crc = calculate_crc(packet);
    if (packet->crc != computed_crc) {
        DBG_WARN("CRC mismatch: computed=0x%02x, received=0x%02x\n",
                 computed_crc, packet->crc);
        debug_hex_dump("Packet dump: ", packet, sizeof(Packet));
        return -1;
    }
    // Packet is valid
    return 0;
}

int send_packet(int socket, Packet *packet, struct sockaddr_ll *addr) {
    packet->start_marker = START_MARKER;

    // Apply masks to ensure fields are within bounds
    packet->type &= TYPE_MASK;
    packet->sequence &= SEQ_MASK;
    packet->length &= LEN_MASK;

    packet->crc = calculate_crc(packet);

    debug_packet("TX", packet);
    ssize_t sent = sendto(socket, packet, sizeof(Packet), 0,
                          (struct sockaddr *)addr, sizeof(*addr));
    if (sent < 0) {
        DBG_ERROR("sendto failed: %s\n", strerror(errno));
        return -1;
    }

    return sent;
}

int receive_packet(int socket, Packet *packet, struct sockaddr_ll *addr) {
    socklen_t addr_len = sizeof(*addr);

    while (1) {
        ssize_t received = recvfrom(socket, packet, sizeof(Packet), 0,
                                    (struct sockaddr *)addr, &addr_len);
        if (received <= 0) {
            DBG_TRACE("No packet received or error: %s\n", strerror(errno));
            return -1;
        }

        if (received < sizeof(Packet)) {
            DBG_WARN("Packet too small: %zd bytes\n", received);
            continue;
        }

        if (validate_packet(packet) != 0) {
            // Invalid packet, discard and continue
            continue;
        }

        debug_packet("RX", packet);
        return received;
    }
}

int wait_for_ack(int socket, Packet *packet, struct sockaddr_ll *addr, uint8_t expected_type) {
    int retries = 0;

    while (retries < MAX_RETRIES) {
        if (receive_packet(socket, packet, addr) > 0) {
            if ((packet->type & TYPE_MASK) == expected_type) {
                return 0;
            }
            if ((packet->type & TYPE_MASK) == PKT_NACK) {
                DBG_WARN("Received NACK\n");
                return -1;
            }
        }
        retries++;
        DBG_WARN("Timeout waiting for ACK, retry %d/%d\n", retries, MAX_RETRIES);
        usleep(RETRY_DELAY_MS * 1000);
    }
    return -1;
}
