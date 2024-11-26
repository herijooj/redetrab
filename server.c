// Server.c - Server-side file backup, restore, and verification ============================================
#include "sockets.h"
// Add the following line to include debug.h
#include "debug.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <limits.h>

#define BACKUP_DIR "./backup/"
#define STATE_IDLE 0
#define STATE_RECEIVING 1

static int current_state = STATE_IDLE;
static int current_fd = -1;

void handle_backup(int socket, Packet *packet, struct sockaddr_ll *addr);
void handle_restore(int socket, Packet *packet, struct sockaddr_ll *addr);
void handle_verify(int socket, Packet *packet, struct sockaddr_ll *addr);
void handle_data_packet(int socket, Packet *packet, int fd, struct sockaddr_ll *addr, struct TransferStats *stats);
void send_ack(int socket, struct sockaddr_ll *addr, uint8_t type);
void send_error(int socket, struct sockaddr_ll *addr, uint8_t error_code);

int main(int argc, char *argv[]) {
    debug_init();  // Initialize debug system
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        exit(1);
    }

    int socket = cria_raw_socket(argv[1]);
    Packet packet = {0};
    packet.node_type = NODE_SERVER;  // Set server node type
    mkdir(BACKUP_DIR, 0777);
    struct sockaddr_ll client_addr;

    while (1) {
        if (receive_packet(socket, &packet, &client_addr, NODE_SERVER) > 0) {
            switch (packet.type & TYPE_MASK) {  // Ensure consistent mask usage
                case PKT_BACKUP:
                    if (current_state != STATE_IDLE) {
                        send_error(socket, &client_addr, ERR_SEQUENCE);
                        break;
                    }
                    current_state = STATE_RECEIVING;
                    handle_backup(socket, &packet, &client_addr);
                    current_state = STATE_IDLE;
                    break;

                case PKT_DATA:
                    if (current_state != STATE_RECEIVING || current_fd < 0) {
                        send_error(socket, &client_addr, ERR_SEQUENCE);
                        break;
                    }
                    handle_data_packet(socket, &packet, current_fd, &client_addr, NULL);
                    break;

                case PKT_END_TX:
                    if (current_state != STATE_RECEIVING || current_fd < 0) {
                        send_error(socket, &client_addr, ERR_SEQUENCE);
                        break;
                    }
                    DBG_INFO("End of transmission received\n");
                    close(current_fd);
                    current_fd = -1;
                    current_state = STATE_IDLE;
                    packet.type = PKT_OK_CHSUM;
                    send_packet(socket, &packet, &client_addr);
                    break;

                case PKT_RESTORE:
                    if (current_state != STATE_IDLE) {
                        send_error(socket, &client_addr, ERR_SEQUENCE);
                        break;
                    }
                    handle_restore(socket, &packet, &client_addr);
                    break;

                case PKT_VERIFY:
                    if (current_state != STATE_IDLE) {
                        send_error(socket, &client_addr, ERR_SEQUENCE);
                        break;
                    }
                    handle_verify(socket, &packet, &client_addr);
                    break;
            }
        }
    }

    return 0;
}

void handle_data_packet(int socket, Packet *packet, int fd, struct sockaddr_ll *addr, struct TransferStats *stats) {
    if (!stats) {
        DBG_ERROR("Transfer stats not initialized!\n");
        send_error(socket, addr, ERR_SEQUENCE);
        return;
    }

    static uint8_t expected_seq = 0;
    size_t data_len = ntohs(packet->length) & LEN_MASK;  // Convert from network byte order    
    if (data_len > MAX_DATA_SIZE) {
        DBG_ERROR("Invalid data length: %zu\n", data_len);
        send_error(socket, addr, ERR_SEQUENCE);
        return;
    }
    
    // Validate total bytes received
    if (stats->total_received + data_len > stats->total_expected) {
        DBG_ERROR("Received more data than expected!\n");
        send_error(socket, addr, ERR_SEQUENCE);
        return;
    }
    
    DBG_INFO("DATA packet: seq=%d/%d, len=%zu, total=%zu/%zu\n", 
             packet->sequence & SEQ_MASK, expected_seq,
             data_len, stats->total_received, stats->total_expected);
    
    // Sequence validation
    if ((packet->sequence & SEQ_MASK) != expected_seq) {
        DBG_ERROR("Sequence mismatch: expected %d, got %d\n", 
                expected_seq, packet->sequence & SEQ_MASK);
        stats->had_errors = 1;
        send_error(socket, addr, ERR_SEQUENCE);
        return;
    }
    
    // Write with validation
    ssize_t written = 0;
    size_t remaining = data_len;
    char *buf_ptr = packet->data;
    
    while (remaining > 0) {
        written = write(fd, buf_ptr, remaining);
        if (written <= 0) {
            DBG_ERROR("Write failed: %s\n", strerror(errno));
            stats->had_errors = 1;
            send_error(socket, addr, ERR_NO_SPACE);
            return;
        }
        remaining -= written;
        buf_ptr += written;
    }
    
    transfer_update_stats(stats, data_len, packet->sequence);
    expected_seq = (expected_seq + 1) & SEQ_MASK;
    expected_seq = (expected_seq + 1) & SEQ_MASK;
    
    // Add validation for total bytes received
    if (stats->total_received + data_len > stats->total_expected) {
        DBG_ERROR("Received more data than expected!\n");
        stats->had_errors = 1;
        send_error(socket, addr, ERR_SEQUENCE);
        return;
    }

    // Send acknowledgment
    Packet ack = {0};
    ack.start_marker = START_MARKER;
    ack.proto_marker = PROTO_MARKER;
    ack.node_type = NODE_SERVER;
    ack.type = PKT_OK;  // Use defined constant
    ack.sequence = packet->sequence & SEQ_MASK;
    send_packet(socket, &ack, addr);

}


void handle_backup(int socket, Packet *packet, struct sockaddr_ll *addr) {
    // Extract file size and filename
    char *filename = packet->data;
    size_t file_size = *((size_t *)(packet->data + strlen(packet->data) + 1));
    
    struct TransferStats stats;
    // Correct the transfer_init_stats function call by removing the extra 'filename' argument
    transfer_init_stats(&stats, file_size);
    DBG_INFO("Starting backup: file=%s, expected_size=%zu\n", 
             filename, file_size);

    char filepath[PATH_MAX];
    snprintf(filepath, sizeof(filepath), "%s%s", BACKUP_DIR, filename);
    
    int fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        DBG_ERROR("Cannot open file for writing: %s\n", strerror(errno));
        send_error(socket, addr, ERR_NO_ACCESS);
        return;
    }
    current_fd = fd;

    // Set longer timeout for large files
    if (set_socket_timeout(socket, SOCKET_TIMEOUT_MS) < 0) {
        DBG_ERROR("Failed to set transfer timeout\n");
        send_error(socket, addr, ERR_TIMEOUT);
        close(current_fd);
        current_fd = -1;
        return;
    }

    // Send initial ACKs
    send_ack(socket, addr, PKT_ACK);
    send_ack(socket, addr, PKT_OK_SIZE);

    uint8_t expected_seq = 0;
    int timeout_count = 0;

    while (stats.total_received < file_size) {
        ssize_t recv_size = receive_packet(socket, packet, addr, NODE_SERVER);
        
        if (recv_size <= 0) {
            if (++timeout_count >= 3) {
                DBG_ERROR("Transfer timeout after 3 attempts\n");
                send_error(socket, addr, ERR_TIMEOUT);
                break;
            }
            continue;
        }
        timeout_count = 0;

        if (recv_size < sizeof(struct Packet)) {
            DBG_WARN("Received undersized packet: %zd bytes\n", recv_size);
            debug_hex_dump("Raw packet: ", packet, recv_size);
            continue;
        }

        switch (packet->type & TYPE_MASK) {
            case PKT_DATA:
                size_t data_len = packet->length & LEN_MASK;
                DBG_INFO("Received DATA: seq=%d/%d, size=%zu, total=%zu/%zu\n",
                        packet->sequence & SEQ_MASK, expected_seq,
                        data_len, stats.total_received, file_size);

                if ((packet->sequence & SEQ_MASK) != expected_seq) {
                    DBG_ERROR("Sequence mismatch: expected %d, got %d\n",
                            expected_seq, packet->sequence & SEQ_MASK);
                    send_error(socket, addr, ERR_SEQUENCE);
                    continue;
                }

                if (data_len > MAX_DATA_SIZE || 
                    stats.total_received + data_len > file_size) {
                    DBG_ERROR("Invalid data length: %zu\n", data_len);
                    send_error(socket, addr, ERR_SEQUENCE);
                    continue;
                }

                ssize_t written = write(fd, packet->data, data_len);
                if (written != data_len) {
                    DBG_ERROR("Write failed: %s\n", strerror(errno));
                    send_error(socket, addr, ERR_NO_SPACE);
                    break;
                }
                expected_seq = (expected_seq + 1) & SEQ_MASK;
                send_ack(socket, addr, PKT_OK);

                float progress = (float)stats.total_received / file_size * 100;
                DBG_INFO("Progress: %.1f%% (%zu/%zu bytes)\n", 
                        progress, stats.total_received, file_size);
                break;

            case PKT_END_TX:
                DBG_INFO("Received END_TX\n");
                print_transfer_summary(&stats);
                
                if (stats.total_received == file_size) {
                    packet->type = PKT_OK_CHSUM;
                    send_packet(socket, packet, addr);
                    DBG_INFO("Transfer completed successfully\n");
                } else {
                    DBG_ERROR("Incomplete transfer: %zu/%zu bytes\n",
                             stats.total_received, file_size);
                    send_error(socket, addr, ERR_SEQUENCE);
                }
                close(current_fd);
                current_fd = -1;
                return;

            default:
                DBG_WARN("Unexpected packet type: 0x%02x\n", packet->type);
                send_error(socket, addr, ERR_SEQUENCE);
                break;
        }
    }
    
    // Reset timeout to default before returning
    set_socket_timeout(socket, TIMEOUT_SEC * 1000);
    close(current_fd);
    current_fd = -1;
}

void handle_restore(int socket, Packet *packet, struct sockaddr_ll *addr) {
    DBG_INFO("Starting restore for file: %s\n", packet->data);
    char filepath[PATH_MAX];
    
    snprintf(filepath, sizeof(filepath), "%s%s", BACKUP_DIR, packet->data);
    
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        send_error(socket, addr, ERR_NOT_FOUND);
        return;
    }
    
    // Set timeout for restore operation
    if (set_socket_timeout(socket, SOCKET_TIMEOUT_MS) < 0) {
        DBG_ERROR("Failed to set restore timeout\n");
        send_error(socket, addr, ERR_TIMEOUT);
        close(fd);
        return;
    }
    
    char buffer[MAX_DATA_SIZE];
    ssize_t bytes;
    uint8_t seq = 0;
    
    current_state = STATE_RECEIVING;
    
    while ((bytes = read(fd, buffer, MAX_DATA_SIZE)) > 0) {
        Packet data = {0};
        data.type = PKT_DATA;
        data.sequence = seq++;
        data.length = bytes;
        memcpy(data.data, buffer, bytes);
        
        DBG_INFO("Sending restore chunk: %zd bytes\n", bytes);
        send_packet(socket, &data, addr);
    }
    
    // Reset timeout before returning
    set_socket_timeout(socket, TIMEOUT_SEC * 1000);
    current_state = STATE_IDLE;
    close(fd);
}

void handle_verify(int socket, Packet *packet, struct sockaddr_ll *addr) {
    DBG_INFO("Verifying file: %s\n", packet->data);
    char filepath[PATH_MAX];
    
    snprintf(filepath, sizeof(filepath), "%s%s", BACKUP_DIR, packet->data);
    
    struct stat st;
    if (stat(filepath, &st) == 0) {
        send_ack(socket, addr, PKT_ACK);
    } else {
        send_error(socket, addr, ERR_NOT_FOUND);
    }
}

void send_ack(int socket, struct sockaddr_ll *addr, uint8_t type) {
    Packet ack = {0};
    ack.start_marker = START_MARKER;
    ack.proto_marker = PROTO_MARKER;
    ack.node_type = NODE_SERVER;
    ack.type = type;
    ack.sequence = 0;
    ack.length = 0;
    send_packet(socket, &ack, addr);
}

void send_error(int socket, struct sockaddr_ll *addr, uint8_t error_code) {
    Packet error = {0};
    error.start_marker = START_MARKER;
    error.proto_marker = PROTO_MARKER;
    error.node_type = NODE_SERVER;
    error.type = PKT_ERROR;
    error.data[0] = error_code;
    error.length = 1;
    send_packet(socket, &error, addr);
}

// ==========================================================================================================