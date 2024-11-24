#include "sockets.h"
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
void handle_data_packet(int socket, Packet *packet, int fd, struct sockaddr_ll *addr);
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
            switch (packet.type & 0x1F) {
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
                    handle_data_packet(socket, &packet, current_fd, &client_addr);
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

void handle_data_packet(int socket, Packet *packet, int fd, struct sockaddr_ll *addr) {
    static uint8_t expected_seq = 0;
    static size_t total_bytes = 0;
    
    size_t data_len = packet->length & LEN_MASK;
    DBG_INFO("Received DATA packet: seq=%d/%d, len=%zu, total=%zu\n", 
             packet->sequence & SEQ_MASK, expected_seq,
             data_len, total_bytes + data_len);
    
    debug_packet("RX (DATA)", packet);
    
    // Validate sequence number with proper masking
    if ((packet->sequence & SEQ_MASK) != expected_seq) {
        DBG_WARN("Sequence mismatch: expected %d, got %d (raw=%d)\n", 
                expected_seq, packet->sequence & SEQ_MASK, packet->sequence);
        send_error(socket, addr, ERR_SEQUENCE);
        return;
    }
    
    ssize_t written = write(fd, packet->data, data_len);
    if (written < 0) {
        DBG_ERROR("Write failed: %s\n", strerror(errno));
        send_error(socket, addr, ERR_NO_SPACE);
        return;
    }
    
    if (written != data_len) {
        DBG_ERROR("Partial write: %zd of %zu bytes\n", written, data_len);
        send_error(socket, addr, ERR_NO_SPACE);
        return;
    }
    
    total_bytes += written;
    DBG_INFO("Successfully wrote %zu bytes (total: %zu)\n", data_len, total_bytes);
    expected_seq = (expected_seq + 1) & SEQ_MASK;
    
    // Send properly formatted ACK
    Packet response = {0};
    response.start_marker = START_MARKER;
    response.proto_marker = PROTO_MARKER;
    response.node_type = NODE_SERVER;
    response.type = PKT_OK;
    response.sequence = packet->sequence & SEQ_MASK;
    response.length = 0;
    
    debug_packet("TX (ACK)", &response);
    send_packet(socket, &response, addr);
}

void handle_backup(int socket, Packet *packet, struct sockaddr_ll *addr) {
    DBG_INFO("Starting backup for file: %s\n", packet->data);
    char filepath[PATH_MAX];
    
    snprintf(filepath, sizeof(filepath), "%s%s", BACKUP_DIR, packet->data);
    
    int fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        DBG_ERROR("Cannot open file for writing: %s\n", strerror(errno));
        send_error(socket, addr, ERR_NO_ACCESS);
        return;
    }
    current_fd = fd;

    // First send ACK for the backup request
    Packet ack = {0};
    ack.start_marker = START_MARKER;
    ack.proto_marker = PROTO_MARKER;
    ack.node_type = NODE_SERVER;
    ack.type = PKT_ACK;
    ack.sequence = 0;
    ack.length = 0;
    
    DBG_INFO("Sending initial ACK: type=0x%02x\n", ack.type);
    if (send_packet(socket, &ack, addr) < 0) {
        DBG_ERROR("Failed to send initial ACK\n");
        close(fd);
        return;
    }
    
    // Then send size acknowledgment
    Packet response = {0};
    response.start_marker = START_MARKER;
    response.proto_marker = PROTO_MARKER;
    response.node_type = NODE_SERVER;
    response.type = PKT_OK_SIZE;
    response.sequence = 0;
    response.length = 0;
    
    DBG_INFO("Sending size acknowledgment: type=0x%02x\n", response.type);
    debug_packet("TX (Size Acknowledgment)", &response);
    
    if (send_packet(socket, &response, addr) < 0) {
        DBG_ERROR("Failed to send size acknowledgment\n");
        close(fd);
        return;
    }

    // Rest of handle_backup remains the same
    while (1) {
        if (receive_packet(socket, packet, addr, NODE_SERVER) <= 0) {
            DBG_WARN("Receive timeout\n");
            send_error(socket, addr, ERR_TIMEOUT);
            break;
        }
        
        switch (packet->type & 0x1F) {
            case PKT_DATA:
                handle_data_packet(socket, packet, fd, addr);
                break;
            case PKT_END_TX:
                DBG_INFO("End of transmission received\n");
                response.type = PKT_OK_CHSUM;
                send_packet(socket, &response, addr);
                close(fd);
                return;
            default:
                DBG_WARN("Unexpected packet type: 0x%02x\n", packet->type);
                send_error(socket, addr, ERR_SEQUENCE);
                break;
        }
    }
    close(fd);
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

