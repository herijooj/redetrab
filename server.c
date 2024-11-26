// Server.c - Server-side file backup, restore, and verification ============================================
#include "sockets.h"
#include "debug.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <limits.h>

#define BACKUP_DIR "./backup/"
#define STATE_IDLE 0
#define STATE_RECEIVING 1

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_RESET   "\x1b[0m"

static int current_state = STATE_IDLE;
static int current_fd = -1;

void handle_backup(int socket, Packet *packet, struct sockaddr_ll *addr, struct TransferStats *stats);
void handle_restore(int socket, Packet *packet, struct sockaddr_ll *addr);
void handle_verify(int socket, Packet *packet, struct sockaddr_ll *addr);
void handle_data_packet(int socket, Packet *packet, int fd, struct sockaddr_ll *addr, struct TransferStats *stats);
void send_ack(int socket, struct sockaddr_ll *addr, uint8_t type);
void send_error(int socket, struct sockaddr_ll *addr, uint8_t error_code);

void display_help(const char* program_name) {
    printf(ANSI_COLOR_BLUE "NARBS Server (Not A Real Backup Solution)\n" ANSI_COLOR_RESET);
    
    printf(ANSI_COLOR_GREEN "Usage:\n" ANSI_COLOR_RESET);
    printf("  %s <interface>\n\n", program_name);
    
    printf(ANSI_COLOR_YELLOW "Description:\n" ANSI_COLOR_RESET);
    printf("  Server component that handles:\n");
    printf("  • File backup requests\n");
    printf("  • File restoration requests\n");
    printf("  • Backup verification requests\n\n");
    
    printf(ANSI_COLOR_BLUE "Storage:\n" ANSI_COLOR_RESET);
    printf("  Files are stored in: %s\n\n", BACKUP_DIR);
    
    printf(ANSI_COLOR_YELLOW "Options:\n" ANSI_COLOR_RESET);
    printf("  -h        - Display this help message");
}

int main(int argc, char *argv[]) {
    debug_init();  // Initialize debug system

    if (argc == 2 && strcmp(argv[1], "-h") == 0) {
        display_help(argv[0]);
        return 0;
    }

    if (argc != 2) {
        fprintf(stderr, ANSI_COLOR_RED "Error: Invalid number of arguments\n" ANSI_COLOR_RESET);
        fprintf(stderr, "Use '%s -h' for help\n", argv[0]);
        exit(1);
    }

    umask(0);  // For file creation permissions
    
    // Create socket only after argument validation
    int socket = cria_raw_socket(argv[1]);
    if (socket < 0) {
        fprintf(stderr, ANSI_COLOR_RED "Error: Could not create socket on interface %s\n" ANSI_COLOR_RESET, argv[1]);
        exit(1);
    }

    Packet packet = {0};
    packet.node_type = NODE_SERVER;  // Set server node type
    mkdir(BACKUP_DIR, 0777);
    struct sockaddr_ll client_addr;
    struct TransferStats stats;

    while (1) {
        if (receive_packet(socket, &packet, &client_addr, NODE_SERVER) > 0) {
            switch (packet.type & TYPE_MASK) {  // Ensure consistent mask usage
                case PKT_BACKUP:
                    if (current_state != STATE_IDLE) {
                        send_error(socket, &client_addr, ERR_SEQUENCE);
                        break;
                    }
                    current_state = STATE_RECEIVING;
                    // Initialize stats with expected file size
                    size_t expected_file_size = *((size_t *)(packet.data + strlen(packet.data) + 1));
                    transfer_init_stats(&stats, expected_file_size);
                    // Pass stats to handle_backup
                    handle_backup(socket, &packet, &client_addr, &stats);
                    // Do not reset current_state here
                    break;

                case PKT_DATA:
                    if (current_state != STATE_RECEIVING || current_fd < 0) {
                        send_error(socket, &client_addr, ERR_SEQUENCE);
                        break;
                    }
                    // Pass stats to handle_data_packet
                    handle_data_packet(socket, &packet, current_fd, &client_addr, &stats);
                    break;

                case PKT_END_TX:
                    if (current_state != STATE_RECEIVING || current_fd < 0) {
                        send_error(socket, &client_addr, ERR_SEQUENCE);
                        break;
                    }
                    DBG_INFO("Received END_TX\n");
                    print_transfer_summary(&stats);

                    if (stats.total_received == stats.total_expected) {
                        packet.type = PKT_OK_CHSUM;
                        send_packet(socket, &packet, &client_addr);
                        DBG_INFO("Transfer completed successfully\n");
                    } else {
                        DBG_ERROR("Incomplete transfer: %zu/%zu bytes\n",
                                  stats.total_received, stats.total_expected);
                        send_error(socket, &client_addr, ERR_SEQUENCE);
                    }
                    close(current_fd);
                    current_fd = -1;
                    current_state = STATE_IDLE; // Reset state after transfer
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

                case PKT_ERROR:
                    DBG_ERROR("Received error from client: code %d\n", packet.data[0]);

                    // Perform any necessary cleanup
                    if (current_fd >= 0) {
                        close(current_fd);
                        current_fd = -1;
                    }
                    current_state = STATE_IDLE;

                    // Optionally, send an acknowledgment or perform other actions
                    break;
            }
        }
    }

    return 0;
}

void handle_data_packet(int socket, Packet *packet, int fd, struct sockaddr_ll *addr, struct TransferStats *stats) {
    // Use stats->expected_seq instead
    size_t data_len = packet->length & LEN_MASK;  // Length is already in host byte order

    // Validate total bytes received
    if (stats->total_received + data_len > stats->total_expected) {
        DBG_ERROR("Received more data than expected!\n");
        send_error(socket, addr, ERR_SEQUENCE);
        return;
    }

    DBG_INFO("DATA packet: seq=%d/%d, len=%zu, total=%zu/%zu\n",
             packet->sequence & SEQ_MASK, stats->expected_seq,
             data_len, stats->total_received, stats->total_expected);

    // Sequence validation
    if ((packet->sequence & SEQ_MASK) != stats->expected_seq) {
        DBG_ERROR("Sequence mismatch: expected %d, got %d\n",
                stats->expected_seq, packet->sequence & SEQ_MASK);
        stats->had_errors = 1;
        send_error(socket, addr, ERR_SEQUENCE);
        return;
    }

    // Write with validation
    ssize_t written = write(fd, packet->data, data_len);
    if (written != data_len) {
        DBG_ERROR("Write failed: %s\n", strerror(errno));
        stats->had_errors = 1;
        send_error(socket, addr, ERR_NO_SPACE);
        return;
    }

    // Update stats and increment sequence number
    stats->total_received += written;
    stats->packets_processed++;
    stats->last_sequence = packet->sequence & SEQ_MASK;

    // Increment expected sequence number
    stats->expected_seq = (stats->expected_seq + 1) & SEQ_MASK;

    DBG_INFO("Updated stats - received: %zu/%zu bytes, packets: %zu\n",
             stats->total_received, stats->total_expected, stats->packets_processed);

    // Print progress
    float progress = (float)stats->total_received / stats->total_expected * 100;
    DBG_INFO("Progress: %.1f%% (%zu/%zu bytes)\n",
             progress, stats->total_received, stats->total_expected);

    // Send acknowledgment
    Packet ack = {0};
    ack.start_marker = START_MARKER;
    ack.proto_marker = PROTO_MARKER;
    ack.node_type = NODE_SERVER;
    ack.type = PKT_OK;
    ack.sequence = packet->sequence & SEQ_MASK;
    send_packet(socket, &ack, addr);
}

void handle_backup(int socket, Packet *packet, struct sockaddr_ll *addr, struct TransferStats *stats) {
    // Extract file size and filename
    char *filename = packet->data;
    size_t file_size = *((size_t *)(packet->data + strlen(packet->data) + 1));
    
    // Initialize stats with expected size
    memset(stats, 0, sizeof(struct TransferStats));
    stats->total_expected = file_size;
    stats->total_received = 0;
    stats->packets_processed = 0;
    stats->expected_seq = 0;
    stats->had_errors = 0;
    
    DBG_INFO("Starting backup: file=%s, expected_size=%zu\n", filename, file_size);

    char filepath[PATH_MAX];
    snprintf(filepath, sizeof(filepath), "%s%s", BACKUP_DIR, filename);
    
    int fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0666);
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
        data.start_marker = START_MARKER;
        data.proto_marker = PROTO_MARKER;
        data.node_type = NODE_SERVER;
        data.type = PKT_DATA;
        data.sequence = seq++;
        data.length = bytes;
        memcpy(data.data, buffer, bytes);
        
        DBG_INFO("Sending restore chunk: %zd bytes\n", bytes);
        send_packet(socket, &data, addr);
    }
    
    // Send END_TX after all data
    Packet end_tx = {0};
    end_tx.start_marker = START_MARKER;
    end_tx.proto_marker = PROTO_MARKER;
    end_tx.node_type = NODE_SERVER;
    end_tx.type = PKT_END_TX;
    end_tx.sequence = 0;
    end_tx.length = 0;
    send_packet(socket, &end_tx, addr);
    DBG_INFO("Sent END_TX packet\n");
    
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

// End of server.c
