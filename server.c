#define SERVER_MODE
#include "sockets.h"
#include "debug.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <limits.h>

#define BACKUP_DIR "./backup/"

typedef enum {
    STATE_IDLE = 0,
    STATE_RECEIVING = 1,
    STATE_ERROR = 2
} ServerState;

typedef struct {
    ServerState state;
    int current_fd;
    char backup_path[PATH_MAX];
} ServerContext;

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
    size_t data_len = GET_SIZE(packet->size_seq_type);

    if (data_len > MAX_DATA_SIZE) {
        DBG_ERROR("Invalid packet length: %zu (max %d)\n", data_len, MAX_DATA_SIZE);
        send_error(socket, addr, ERR_SEQUENCE, true);
        return;
    }

    if (GET_SEQUENCE(packet->size_seq_type) > SEQ_NUM_MAX) {
        DBG_ERROR("Invalid sequence number: %d (max %d)\n", GET_SEQUENCE(packet->size_seq_type), SEQ_NUM_MAX);
        send_error(socket, addr, ERR_SEQUENCE, true);
        return;
    }

    DBG_INFO("DATA packet: seq=%d/%d, len=%zu, total=%zu/%zu\n", GET_SEQUENCE(packet->size_seq_type), stats->expected_seq, data_len, stats->total_received, stats->total_expected);

    // Sequence Number Handling
    uint8_t recv_seq = GET_SEQUENCE(packet->size_seq_type);
    uint8_t exp_seq = stats->expected_seq;

    // Add detailed validation debugging
    uint8_t computed_crc = calculate_crc(packet);
    debug_packet_validation(packet, computed_crc);

    // Sequence validation with wrap-around handling
    if (recv_seq != exp_seq) {
        if ((recv_seq == 0 && exp_seq == SEQ_NUM_MAX) || 
            SEQ_DIFF(recv_seq, exp_seq) <= SEQ_NUM_MAX/2) {
            // Valid sequence progression
            transfer_update_stats(stats, data_len, recv_seq);
        } else {
            debug_sequence_error(stats, recv_seq);
            stats->had_errors = 1;
            send_error(socket, addr, ERR_SEQUENCE, true);
            return;
        }
    } else {
        transfer_update_stats(stats, data_len, recv_seq);
    }

    ssize_t written = write(fd, packet->data, data_len);
    if (written != data_len) {
        DBG_ERROR("Write failed: %s\n", strerror(errno));
        stats->had_errors = 1;
        send_error(socket, addr, ERR_NO_SPACE, true);
        return;
    }

    // Update total_received only once after successful write
    stats->total_received += written;

    // Remove redundant updates
    // stats->packets_processed++; // Already done in transfer_update_stats
    // stats->last_sequence = recv_seq; // Already done in transfer_update_stats
    // stats->expected_seq = (recv_seq + 1) & SEQ_NUM_MAX; // Already done in transfer_update_stats

    DBG_INFO("Updated stats - received: %zu/%zu bytes, packets: %zu\n", stats->total_received, stats->total_expected, stats->packets_processed);

    float progress = (float)(stats->total_received * 100.0) / stats->total_expected;
    DBG_INFO("Progress: %.1f%% (%zu/%zu bytes)\n", progress, stats->total_received, stats->total_expected);

    // Add transfer progress debugging
    debug_transfer_progress(stats, packet);

    // Send ACK with Correct Sequence Number
    Packet ack = {0};
    ack.start_marker = START_MARKER;
    SET_TYPE(ack.size_seq_type, PKT_OK);
    SET_SEQUENCE(ack.size_seq_type, recv_seq);
    SET_SIZE(ack.size_seq_type, 0);
    ack.crc = calculate_crc(&ack); // is_send = true
    send_packet(socket, &ack, addr, true);
}

void handle_backup(int socket, Packet *packet, struct sockaddr_ll *addr, struct TransferStats *stats) {
    char *filename = packet->data;
    char *base_filename = strrchr(filename, '/');
    if (base_filename) {
        base_filename++;
    } else {
        base_filename = filename;
    }
    
    size_t file_size = *((size_t *)(packet->data + strlen(packet->data) + 1));
    memset(stats, 0, sizeof(struct TransferStats));
    stats->total_expected = file_size;

    DBG_INFO("Starting backup: file=%s, expected_size=%zu\n", filename, file_size);

    char filepath[PATH_MAX];
    snprintf(filepath, sizeof(filepath), "%s%s", BACKUP_DIR, base_filename);

    int fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) {
        DBG_ERROR("Cannot open file for writing: %s\n", strerror(errno));
        send_error(socket, addr, ERR_NO_ACCESS, true);
        return;
    }
    current_fd = fd;

    if (set_socket_timeout(socket, SOCKET_TIMEOUT_MS) < 0) {
        DBG_ERROR("Failed to set transfer timeout\n");
        send_error(socket, addr, ERR_TIMEOUT, true);
        close(current_fd);
        current_fd = -1;
        return;
    }

    send_ack(socket, addr, PKT_ACK, true);
    send_ack(socket, addr, PKT_OK_SIZE, true);

    // Add initial transfer debugging
    debug_transfer_progress(stats, packet);
}

void handle_restore(int socket, Packet *packet, struct sockaddr_ll *addr) {
    DBG_INFO("Starting restore for file: %s\n", packet->data);
    char filepath[PATH_MAX];
    snprintf(filepath, sizeof(filepath), "%s%s", BACKUP_DIR, packet->data);

    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        DBG_WARN("File not found in backup: %s\n", packet->data);
        send_error(socket, addr, ERR_NOT_FOUND, true);
        return;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        DBG_ERROR("Cannot stat file: %s\n", strerror(errno));
        send_error(socket, addr, ERR_NO_ACCESS, true);
        close(fd);
        return;
    }
    uint64_t total_size = st.st_size;
    DBG_INFO("File size: %lu bytes\n", total_size);

    Packet size_packet = {0};
    size_packet.start_marker = START_MARKER;
    SET_TYPE(size_packet.size_seq_type, PKT_SIZE);
    memcpy(size_packet.data, &total_size, sizeof(size_t));
    SET_SIZE(size_packet.size_seq_type, sizeof(size_t));
    send_packet(socket, &size_packet, addr, true);

    if (set_socket_timeout(socket, SOCKET_TIMEOUT_MS) < 0) {
        DBG_ERROR("Failed to set restore timeout\n");
        send_error(socket, addr, ERR_TIMEOUT, true);
        close(fd);
        return;
    }

    char buffer[MAX_DATA_SIZE];
    ssize_t bytes;
    uint8_t seq = 0;
    current_state = STATE_RECEIVING;
    size_t bytes_sent = 0;

    while ((bytes = read(fd, buffer, MAX_DATA_SIZE)) > 0) {
        Packet data = {0};
        data.start_marker = START_MARKER;
        SET_TYPE(data.size_seq_type, PKT_DATA);
        SET_SEQUENCE(data.size_seq_type, seq & SEQ_NUM_MAX);
        seq = (seq + 1) & SEQ_NUM_MAX;
        SET_SIZE(data.size_seq_type, bytes);
        memcpy(data.data, buffer, bytes);

        size_t remaining = total_size - bytes_sent - bytes;
        DBG_INFO("Preparing chunk: seq=%d, size=%zd, remaining=%zu\n", GET_SEQUENCE(data.size_seq_type), bytes, remaining);
        DBG_INFO("Sending restore chunk: %zd bytes\n", bytes);
        send_packet(socket, &data, addr, true);

        bytes_sent += bytes;

        Packet recv_packet;
        if (receive_packet(socket, &recv_packet, addr, false) > 0) {
            uint8_t expected_ack = (seq - 1) & SEQ_NUM_MAX;
            if (GET_TYPE(recv_packet.size_seq_type) != PKT_OK || 
                (GET_SEQUENCE(recv_packet.size_seq_type) & SEQ_NUM_MAX) != expected_ack) {
                DBG_WARN("Did not receive expected ACK\n");
            }
        } else {
            DBG_WARN("No ACK received, proceeding\n");
        }
    }

    Packet end_tx = {0};
    end_tx.start_marker = START_MARKER;
    SET_TYPE(end_tx.size_seq_type, PKT_END_TX);
    SET_SEQUENCE(end_tx.size_seq_type, 0);
    SET_SIZE(end_tx.size_seq_type, 0);
    send_packet(socket, &end_tx, addr, true);
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
        send_ack(socket, addr, PKT_ACK, true);
    } else {
        send_error(socket, addr, ERR_NOT_FOUND, true);
    }
}

int main(int argc, char *argv[]) {
    debug_init();
    debug_init_error_log("server");

    if (argc == 2 && strcmp(argv[1], "-h") == 0) {
        display_help(argv[0]);
        return 0;
    }

    if (argc != 2) {
        fprintf(stderr, RED "Error: Invalid number of arguments\n" RESET);
        fprintf(stderr, "Use '%s -h' for help\n", argv[0]);
        exit(1);
    }

    umask(0);

    int socket_fd = cria_raw_socket(argv[1]);
    if (socket_fd < 0) {
        fprintf(stderr, RED "Error: Could not create socket on interface %s\n" RESET, argv[1]);
        exit(1);
    }

    Packet packet = {0};
    memset(packet.padding, 0, PAD_SIZE);
    mkdir(BACKUP_DIR, 0777);
    struct sockaddr_ll client_addr;
    struct TransferStats stats;

    while (1) {
        if (receive_packet(socket_fd, &packet, &client_addr, false) > 0) { // is_send = false
            switch (GET_TYPE(packet.size_seq_type)) {
                case PKT_BACKUP:
                    if (current_state != STATE_IDLE) {
                        send_error(socket_fd, &client_addr, ERR_SEQUENCE, true);
                        break;
                    }
                    current_state = STATE_RECEIVING;
                    size_t expected_file_size = *((size_t *)(packet.data + strlen(packet.data) + 1));
                    transfer_init_stats(&stats, expected_file_size);
                    handle_backup(socket_fd, &packet, &client_addr, &stats);
                    break;

                case PKT_DATA:
                    if (current_state != STATE_RECEIVING || current_fd < 0) {
                        send_error(socket_fd, &client_addr, ERR_SEQUENCE, true);
                        break;
                    }
                    handle_data_packet(socket_fd, &packet, current_fd, &client_addr, &stats);
                    break;

                case PKT_END_TX:
                    if (current_state != STATE_RECEIVING || current_fd < 0) {
                        send_error(socket_fd, &client_addr, ERR_SEQUENCE, true);
                        break;
                    }
                    DBG_INFO("Received END_TX\n");
                    print_transfer_summary(&stats);

                    if (stats.total_received == stats.total_expected) {
                        Packet end_tx_ack = {0};
                        end_tx_ack.start_marker = START_MARKER;
                        SET_TYPE(end_tx_ack.size_seq_type, PKT_OK_CHSUM);
                        SET_SEQUENCE(end_tx_ack.size_seq_type, 0);
                        SET_SIZE(end_tx_ack.size_seq_type, 0);
                        end_tx_ack.crc = calculate_crc(&end_tx_ack); // is_send = true
                        send_packet(socket_fd, &end_tx_ack, &client_addr, true);
                        DBG_INFO("Transfer completed successfully\n");
                    } else {
                        DBG_ERROR("Incomplete transfer: %zu/%zu bytes\n", stats.total_received, stats.total_expected);
                        send_error(socket_fd, &client_addr, ERR_SEQUENCE, true);
                    }
                    close(current_fd);
                    current_fd = -1;
                    current_state = STATE_IDLE;
                    break;

                case PKT_RESTORE:
                    if (current_state != STATE_IDLE) {
                        send_error(socket_fd, &client_addr, ERR_SEQUENCE, true);
                        break;
                    }
                    handle_restore(socket_fd, &packet, &client_addr);
                    break;

                case PKT_VERIFY:
                    if (current_state != STATE_IDLE) {
                        send_error(socket_fd, &client_addr, ERR_SEQUENCE, true);
                        break;
                    }
                    handle_verify(socket_fd, &packet, &client_addr);
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