#include "sockets.h"
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

void handle_data_packet(int socket, Packet *packet, int fd, struct sockaddr_ll *addr, struct TransferStats *stats);

void handle_backup(int socket, Packet *packet, struct sockaddr_ll *addr, struct TransferStats *stats);
void handle_restore(int socket, Packet *packet, struct sockaddr_ll *addr);
void handle_verify(int socket, Packet *packet, struct sockaddr_ll *addr);


void display_help(const char* program_name) {
    printf(BLUE "NARBS Server (Not A Real Backup Solution)\n" RESET);

    printf(GREEN "Usage:\n" RESET);
    printf("  %s <interface>\n\n", program_name);

    printf(YELLOW "Description:\n" RESET);
    printf("  Server component that handles:\n");
    printf("  • File backup requests\n");
    printf("  • File restoration requests\n");
    printf("  • Backup verification requests\n\n");

    printf(BLUE "Storage:\n" RESET);
    printf("  Files are stored in: %s\n\n", BACKUP_DIR);

    printf(YELLOW "Options:\n" RESET);
    printf("  -h        - Display this help message");
}

void handle_data_packet(int socket, Packet *packet, int fd, struct sockaddr_ll *addr, struct TransferStats *stats) {
    size_t data_len = packet->length & LEN_MASK;

    // Validate length field
    if (data_len > MAX_DATA_SIZE) {
        DBG_ERROR("Invalid packet length: %zu (max %d)\n", data_len, MAX_DATA_SIZE);
        send_error(socket, addr, ERR_SEQUENCE);
        return;
    }

    // Validate sequence number
    if ((packet->sequence & SEQ_MASK) > SEQ_MASK) {
        DBG_ERROR("Invalid sequence number: %d (max %d)\n", 
                  packet->sequence & SEQ_MASK, SEQ_MASK);
        send_error(socket, addr, ERR_SEQUENCE);
        return;
    }

    if (stats->total_received + data_len > stats->total_expected) {
        DBG_ERROR("Received more data than expected! (%lu + %zu > %lu)\n",
                  stats->total_received, data_len, stats->total_expected);
        send_error(socket, addr, ERR_SEQUENCE);
        return;
    }

    DBG_INFO("DATA packet: seq=%d/%d, len=%zu, total=%zu/%zu\n",
             packet->sequence & SEQ_MASK, stats->expected_seq,
             data_len, stats->total_received, stats->total_expected);

    uint16_t recv_seq = packet->sequence & SEQ_MASK;
    uint16_t exp_seq = stats->expected_seq & SEQ_MASK;

    // Handle wrap-around in sequence numbers
    if (recv_seq != exp_seq) {
        if (recv_seq == 0 && exp_seq == SEQ_MASK) {
            transfer_handle_wrap(stats);
        } else {
            DBG_ERROR("Sequence mismatch: expected %d, got %d (wrap count: %u)\n",
                      exp_seq, recv_seq, stats->wrap_count);
            stats->had_errors = 1;
            send_error(socket, addr, ERR_SEQUENCE);
            return;
        }
    }

    ssize_t written = write(fd, packet->data, data_len);
    if (written != data_len) {
        DBG_ERROR("Write failed: %s\n", strerror(errno));
        stats->had_errors = 1;
        send_error(socket, addr, ERR_NO_SPACE);
        return;
    }

    stats->total_received += written;
    stats->packets_processed++;
    stats->last_sequence = recv_seq;
    stats->expected_seq = (recv_seq + 1) & SEQ_MASK;

    DBG_INFO("Updated stats - received: %zu/%zu bytes, packets: %zu\n",
             stats->total_received, stats->total_expected, stats->packets_processed);

    float progress = (float)(stats->total_received * 100.0) / stats->total_expected;
    DBG_INFO("Progress: %.1f%% (%lu/%lu bytes)\n",
             progress, stats->total_received, stats->total_expected);

    // Send acknowledgment
    Packet ack = {0};
    ack.start_marker = START_MARKER;
    ack.type = PKT_OK;
    ack.sequence = packet->sequence & SEQ_MASK;
    send_packet(socket, &ack, addr);
}

void handle_backup(int socket, Packet *packet, struct sockaddr_ll *addr, struct TransferStats *stats) {
    // Extract file size and filename
    char *filename = packet->data;
    
    // Get just the base filename without path
    char *base_filename = strrchr(filename, '/');
    if (base_filename) {
        base_filename++; // Skip the '/'
    } else {
        base_filename = filename; // No path separator found
    }
    
    size_t file_size = *((size_t *)(packet->data + strlen(packet->data) + 1));

    // Initialize stats with expected size
    memset(stats, 0, sizeof(struct TransferStats));
    stats->total_expected = file_size;
    stats->total_received = 0;
    stats->packets_processed = 0;
    stats->expected_seq = 0;
    stats->wrap_count = 0;
    stats->total_sequences = 0;
    stats->had_errors = 0;

    DBG_INFO("Starting backup: file=%s, expected_size=%zu\n", filename, file_size);

    char filepath[PATH_MAX];
    snprintf(filepath, sizeof(filepath), "%s%s", BACKUP_DIR, base_filename);

    int fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) {
        DBG_ERROR("Cannot open file for writing: %s\n", strerror(errno));
        send_error(socket, addr, ERR_NO_ACCESS);
        return;
    }
    current_fd = fd;

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
        DBG_WARN("File not found in backup: %s\n", packet->data);
        send_error(socket, addr, ERR_NOT_FOUND);
        return;
    }

    // Get file size and send it to the client
    struct stat st;
    if (fstat(fd, &st) < 0) {
        DBG_ERROR("Cannot stat file: %s\n", strerror(errno));
        send_error(socket, addr, ERR_NO_ACCESS);
        close(fd);
        return;
    }
    uint64_t total_size = st.st_size;  // Changed from size_t
    DBG_INFO("File size: %lu bytes\n", total_size);

    Packet size_packet = {0};
    size_packet.start_marker = START_MARKER;
    size_packet.type = PKT_SIZE;
    memcpy(size_packet.data, &total_size, sizeof(size_t));
    size_packet.length = sizeof(size_t);
    send_packet(socket, &size_packet, addr);

    if (set_socket_timeout(socket, SOCKET_TIMEOUT_MS) < 0) {
        DBG_ERROR("Failed to set restore timeout\n");
        send_error(socket, addr, ERR_TIMEOUT);
        close(fd);
        return;
    }

    char buffer[MAX_DATA_SIZE];
    ssize_t bytes;
    uint16_t seq = 0;  // Use uint16_t for sequence numbers

    current_state = STATE_RECEIVING;

    size_t bytes_sent = 0;  // Initialize bytes sent

    while ((bytes = read(fd, buffer, MAX_DATA_SIZE)) > 0) {
        Packet data = {0};
        data.start_marker = START_MARKER;
        data.type = PKT_DATA;
        data.sequence = seq & SEQ_MASK;
        seq = (seq + 1) & SEQ_MASK;
        data.length = bytes & LEN_MASK;
        memcpy(data.data, buffer, bytes);

        size_t remaining = total_size - bytes_sent - bytes;  // Calculate remaining bytes

        DBG_INFO("Preparing chunk: seq=%d, size=%zd, remaining=%zu\n",
                 data.sequence & SEQ_MASK, bytes, remaining);  // Log the chunk details

        DBG_INFO("Sending restore chunk: %zd bytes\n", bytes);
        send_packet(socket, &data, addr);

        bytes_sent += bytes;  // Update bytes sent

        // Wait for ACK from client
        Packet recv_packet;
        if (receive_packet(socket, &recv_packet, addr) > 0) {
            if (recv_packet.type != PKT_OK || ((recv_packet.sequence & SEQ_MASK) != (seq - 1))) {
                DBG_WARN("Did not receive expected ACK\n");
            }
        } else {
            DBG_WARN("No ACK received, proceeding\n");
        }
    }

    // Send END_TX after all data
    Packet end_tx = {0};
    end_tx.start_marker = START_MARKER;
    end_tx.type = PKT_END_TX;
    end_tx.sequence = 0;
    end_tx.length = 0;
    send_packet(socket, &end_tx, addr);
    DBG_INFO("Sent END_TX packet\n");

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

int main(int argc, char *argv[]) {
    debug_init();  // Initialize debug system

    if (argc == 2 && strcmp(argv[1], "-h") == 0) {
        display_help(argv[0]);
        return 0;
    }

    if (argc != 2) {
        fprintf(stderr, RED "Error: Invalid number of arguments\n" RESET);
        fprintf(stderr, "Use '%s -h' for help\n", argv[0]);
        exit(1);
    }

    umask(0);  // For file creation permissions

    int socket = cria_raw_socket(argv[1]);
    if (socket < 0) {
        fprintf(stderr, RED "Error: Could not create socket on interface %s\n" RESET, argv[1]);
        exit(1);
    }

    Packet packet = {0};
    mkdir(BACKUP_DIR, 0777);
    struct sockaddr_ll client_addr;
    struct TransferStats stats;

    while (1) {
        if (receive_packet(socket, &packet, &client_addr) > 0) {
            switch (packet.type & TYPE_MASK) {
                case PKT_BACKUP:
                    if (current_state != STATE_IDLE) {
                        send_error(socket, &client_addr, ERR_SEQUENCE);
                        break;
                    }
                    current_state = STATE_RECEIVING;
                    size_t expected_file_size = *((size_t *)(packet.data + strlen(packet.data) + 1));
                    transfer_init_stats(&stats, expected_file_size);
                    handle_backup(socket, &packet, &client_addr, &stats);
                    break;

                case PKT_DATA:
                    if (current_state != STATE_RECEIVING || current_fd < 0) {
                        send_error(socket, &client_addr, ERR_SEQUENCE);
                        break;
                    }
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
                    current_state = STATE_IDLE;
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

                    if (current_fd >= 0) {
                        close(current_fd);
                        current_fd = -1;
                    }
                    current_state = STATE_IDLE;

                    break;
            }
        }
    }

    return 0;
}