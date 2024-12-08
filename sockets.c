// sockets.c
#include "sockets.h"
#include "debug.h"
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <string.h>

// Function to get interface information
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

// Function to create and bind a raw socket
int cria_raw_socket(char *nome_interface_rede) {
    DBG_INFO("Creating raw socket on interface %s\n", nome_interface_rede);
    int soquete = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (soquete == -1) {
        DBG_ERROR("Error creating socket: Root privileges required!\n");
        exit(-1);
    }
    DBG_TRACE("Socket created successfully with fd=%d\n", soquete);

    struct sockaddr_ll endereco;
    if (get_interface_info(soquete, nome_interface_rede, &endereco) < 0) {
        close(soquete);
        exit(-1);
    }

    if (bind(soquete, (struct sockaddr *)&endereco, sizeof(endereco)) == -1) {
        fprintf(stderr, "Erro ao fazer bind no socket: %s\n", strerror(errno));
        close(soquete);
        exit(-1);
    }

    struct packet_mreq mr = {0};
    mr.mr_ifindex = endereco.sll_ifindex;
    mr.mr_type = PACKET_MR_PROMISC;

    // Enable promiscuous mode
    if (setsockopt(soquete, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) == -1) {
        fprintf(stderr, "Erro ao fazer setsockopt: "
                        "Verifique se a interface de rede foi especificada corretamente.\n");
        close(soquete);
        exit(-1);
    }

    return soquete;
}

// Function to set socket timeout
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

// Simplified CRC calculation
uint8_t calculate_crc(const Packet *packet) {
    if (!packet) return 0;
    
    uint8_t crc = 0;
    
    // Include start_marker and size_seq_type
    crc ^= packet->start_marker;
    crc ^= (packet->size_seq_type >> 8) & 0xFF;
    crc ^= packet->size_seq_type & 0xFF;
    
    // Get the actual data size
    uint8_t size = GET_SIZE(packet->size_seq_type);
    if (size > MAX_DATA_SIZE) {
        size = MAX_DATA_SIZE;
    }
    
    // Process data bytes
    for (int i = 0; i < size; i++) {
        crc ^= (uint8_t)packet->data[i];
    }
    
    DBG_TRACE("Computed CRC: 0x%02x\n", crc);
    return crc;
}

// Simplified CRC validation
int validate_crc(const Packet *packet) {
    if (!packet) return 0;
    uint8_t computed = calculate_crc(packet);
    return computed == packet->crc;
}

// Function to send acknowledgment
void send_ack(int socket, struct sockaddr_ll *addr, uint8_t type, bool is_send) {
    Packet ack = {0};
    ack.start_marker = START_MARKER;
    SET_TYPE(ack.size_seq_type, type);
    SET_SEQUENCE(ack.size_seq_type, 0);
    SET_SIZE(ack.size_seq_type, 0);
    ack.crc = calculate_crc(&ack);
    send_packet(socket, &ack, addr, is_send);
}

// Function to send error packet
void send_error(int socket, struct sockaddr_ll *addr, uint8_t error_code, bool is_send) {
    Packet error = {0};
    error.start_marker = START_MARKER;
    SET_TYPE(error.size_seq_type, PKT_ERROR);
    SET_SEQUENCE(error.size_seq_type, 0);
    SET_SIZE(error.size_seq_type, 1);
    error.data[0] = error_code;
    error.crc = calculate_crc(&error);
    send_packet(socket, &error, addr, is_send);
}

// Function to send a packet ensuring all bytes are sent
int send_packet(int socket, Packet *packet, struct sockaddr_ll *addr, bool is_send) {
    DBG_TRACE("Entering send_packet (socket=%d, is_send=%d)\n", socket, is_send);
    // Recalculate CRC to ensure integrity
    packet->crc = calculate_crc(packet);  // Corrected line
    
    debug_packet("TX", packet);
    DBG_TRACE("Packet type=%d, sequence=%d, size=%d\n", 
              GET_TYPE(packet->size_seq_type),
              GET_SEQUENCE(packet->size_seq_type),
              GET_SIZE(packet->size_seq_type));

    memset(packet->padding, 0, PAD_SIZE);

    ssize_t total_sent = 0;
    ssize_t packet_size = sizeof(Packet);
    uint8_t *buffer = (uint8_t*)packet;

    while (total_sent < packet_size) {
        DBG_TRACE("Attempting to send %zd bytes (total_sent=%zd)\n", 
                  packet_size - total_sent, total_sent);
        ssize_t sent = sendto(socket, buffer + total_sent, packet_size - total_sent, 0,
                              (struct sockaddr *)addr, sizeof(*addr));
        if (sent < 0) {
            DBG_ERROR("sendto failed: %s\n", strerror(errno));
            return -1;
        }
        DBG_TRACE("Sent %zd bytes in this iteration\n", sent);
        total_sent += sent;
    }

    if (total_sent != packet_size) {
        DBG_WARN("Incomplete packet sent: %zd/%zd bytes\n", total_sent, packet_size);
        return -1;
    }

    return 0;
}

// Function to validate packet fields
int validate_packet_fields(Packet *packet) {
    if (!VALIDATE_SEQUENCE(GET_SEQUENCE(packet->size_seq_type))) {
        DBG_ERROR("Invalid sequence number: %d\n", GET_SEQUENCE(packet->size_seq_type));
        return -1;
    }
    if (!VALIDATE_SIZE(GET_SIZE(packet->size_seq_type))) {
        DBG_ERROR("Invalid size: %d\n", GET_SIZE(packet->size_seq_type));
        return -1;
    }
    if (!VALIDATE_TYPE(GET_TYPE(packet->size_seq_type))) {
        DBG_ERROR("Invalid type: %d\n", GET_TYPE(packet->size_seq_type));
        return -1;
    }
    return 0;
}

// Function to validate a packet
int validate_packet(Packet *packet, bool is_send) {
    if (!packet) {
        DBG_ERROR("Null packet received\n");
        return -1;
    }
    
    // Check start marker first
    if (packet->start_marker != START_MARKER) {
        DBG_WARN("Invalid start marker: 0x%02x\n", packet->start_marker);
        return -1;
    }
    
    // Validate packet fields before CRC check
    if (validate_packet_fields(packet) < 0) {
        return -1;
    }
    
    // Final CRC validation
    uint8_t computed_crc = calculate_crc(packet);
    debug_packet_validation(packet, computed_crc);
    
    if (packet->crc != computed_crc) {
        DBG_WARN("CRC mismatch: computed=0x%02x, received=0x%02x\n",
                 computed_crc, packet->crc);
        debug_hex_dump("Packet with CRC error: ", packet, sizeof(Packet));
        return -1;
    }
    
    return 0;
}

// Function to receive a packet with context
ssize_t receive_packet(int socket, Packet *packet, struct sockaddr_ll *addr, bool is_send) {
    DBG_TRACE("Entering receive_packet (socket=%d, is_send=%d)\n", socket, is_send);
    socklen_t addr_len = sizeof(*addr);
    uint8_t buffer[sizeof(Packet)];
    int consecutive_crc_errors = 0;
    
    while (consecutive_crc_errors < MAX_CONSECUTIVE_CRC_ERRORS) {
        DBG_TRACE("Waiting for packet (attempt %d/%d)\n", 
                  consecutive_crc_errors + 1, MAX_CONSECUTIVE_CRC_ERRORS);
        ssize_t received = recvfrom(socket, buffer, sizeof(buffer), 0, 
                                  (struct sockaddr *)addr, &addr_len);
        
        if (received > 0) {
            DBG_TRACE("Received %zd bytes\n", received);
            
            // Add packet length validation
            if (!VALIDATE_PACKET_LENGTH(received)) {
                DBG_ERROR("Invalid packet length: received=%zd, expected=%d-%d\n",
                         received, MIN_PACKET_LENGTH, MAX_PACKET_LENGTH);
                send_error(socket, addr, ERR_SEQUENCE, is_send);
                continue;
            }
        }

        if (received <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                DBG_TRACE("Socket timeout\n");
            } else {
                DBG_ERROR("Receive error: %s\n", strerror(errno));
            }
            return -1;
        }

        if (received < MIN_PACKET_SIZE) {
            DBG_WARN("Packet too small: %zd bytes\n", received);
            continue;
        }

        // Before copying to packet, ensure we copy the full size
        memset(packet, 0, sizeof(Packet));
        memcpy(packet, buffer, sizeof(Packet));  // Changed from 'received' to sizeof(Packet)
        
        DBG_TRACE("Pre-validation: marker=0x%02x, type=%d, seq=%d, size=%d\n",
                  packet->start_marker,
                  GET_TYPE(packet->size_seq_type),
                  GET_SEQUENCE(packet->size_seq_type),
                  GET_SIZE(packet->size_seq_type));

        int validation_result = validate_packet(packet, is_send);
        if (validation_result == 0) {
            debug_packet("RX", packet);
            return received;
        }
        
        if (validation_result == -1) {  // CRC error
            consecutive_crc_errors++;
            if (consecutive_crc_errors < MAX_CONSECUTIVE_CRC_ERRORS) {
                DBG_WARN("CRC error %d/%d, requesting retransmission\n", 
                        consecutive_crc_errors, MAX_CONSECUTIVE_CRC_ERRORS);
                send_error(socket, addr, ERR_CRC, is_send);
                usleep(CRC_ERROR_BACKOFF_MS * 1000);
            }
        }

        if (GET_TYPE(packet->size_seq_type) == PKT_DATA) {
            uint8_t recv_seq = GET_SEQUENCE(packet->size_seq_type);
            DBG_TRACE("Received DATA packet with seq=%u\n", recv_seq);
            
            // Log sequence validation
            debug_packet_validation(packet, packet->crc);
        }
    }
    
    return -1;
}

// Function to send acknowledgment with correct context
int wait_for_ack(int socket, Packet *packet, struct sockaddr_ll *addr, uint8_t expected_type) {
    DBG_TRACE("Entering wait_for_ack (socket=%d, expected_type=%d)\n", socket, expected_type);
    int retries = 0;

    while (retries < MAX_RETRIES) {
        DBG_TRACE("Waiting for ACK (attempt %d/%d)\n", retries + 1, MAX_RETRIES);
        if (receive_packet(socket, packet, addr, false) > 0) { // is_send = false
            uint8_t received_type = GET_TYPE(packet->size_seq_type);
            DBG_TRACE("Received packet type=%d (expected=%d)\n", received_type, expected_type);
            if (received_type == expected_type) {
                return 0;
            }
            if (received_type == PKT_NACK) {
                DBG_WARN("Received NACK\n");
                return -1;
            }
        }
        retries++;
        DBG_WARN("Timeout waiting for ACK, retry %d/%d\n", retries, MAX_RETRIES);
        usleep(RETRY_DELAY_MS * 1000);
    }
    DBG_ERROR("Failed to receive ACK after %d retries\n", MAX_RETRIES);
    return -1;
}

// Initialize packet statistics
void init_packet_stats(struct PacketStats *stats) {
    memset(stats, 0, sizeof(struct PacketStats));
}

// Update packet statistics
void update_packet_stats(struct PacketStats *stats, size_t bytes, int is_send) {
    stats->total_bytes += bytes;
    if (is_send) {
        stats->packets_sent++;
    } else {
        stats->packets_received++;
    }
}

void init_packet_sequence(struct Packet *packet) {
    if (!packet) return;
    SET_SEQUENCE(packet->size_seq_type, INITIAL_SEQUENCE);
}

int validate_sequence_order(uint8_t received, uint8_t expected) {
    if (received == expected) return 0;
    
    // Handle wrap-around case
    if (expected == 0 && received == SEQ_NUM_MAX) return 0;
    
    // Check if sequence is within valid range
    int diff = SEQ_DIFF(received, expected);
    if (diff <= SEQ_NUM_MAX/2) return 0;
    
    DBG_ERROR("Invalid sequence order: received=%u expected=%u\n", received, expected);
    return -1;
}
