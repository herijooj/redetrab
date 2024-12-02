#include "sockets.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <ctype.h>

void backup_file(int socket, char *filename, struct sockaddr_ll *addr);
int restore_file(int socket, char *filename, struct sockaddr_ll *addr);
void verify_file(int socket, char *filename, struct sockaddr_ll *addr);

void display_help(const char* program_name) {
    printf(BLUE "NARBS Client (Not A Real Backup Solution)\n" RESET);
    printf(GREEN "Usage:\n" RESET);
    printf("  %s <interface> <command> <filename>\n\n", program_name);
    printf(YELLOW "Commands:\n" RESET);
    printf("  backup    - Create a backup of a file\n");
    printf("  restaura  - Restore a file from backup\n");
    printf("  verifica  - Verify if a file exists in backup\n\n");
    printf(YELLOW "Options:\n" RESET);
    printf("  -h        - Display this help message");
}

int parse_mac_address(const char *mac_str, unsigned char *mac_addr) {
    int values[6];
    if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x",
               &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5]) != 6) {
        return -1;
    }
    for (int i = 0; i < 6; i++) {
        if (values[i] < 0 || values[i] > 255) {
            return -1;
        }
        mac_addr[i] = (unsigned char)values[i];
    }
    return 0;
}

int read_mac_from_config(const char *config_file, unsigned char *mac_addr) {
    FILE *file = fopen(config_file, "r");
    if (!file) {
        DBG_ERROR("Cannot open config file %s: %s\n", config_file, strerror(errno));
        return -1;
    }
    char line[256];
    char mac_str[18] = {0};
    while (fgets(line, sizeof(line), file)) {
        if (sscanf(line, "server_mac=%17s", mac_str) == 1) {
            fclose(file);
            return parse_mac_address(mac_str, mac_addr);
        }
    }
    fclose(file);
    return -1;
}

void backup_file(int socket, char *filename, struct sockaddr_ll *addr) {
    DBG_INFO("Starting backup of %s\n", filename);

    char resolved_path[PATH_MAX];
    if (realpath(filename, resolved_path) == NULL) {
        DBG_ERROR("Cannot resolve file path %s: %s\n", filename, strerror(errno));
        fprintf(stderr, "Error: Invalid file path '%s': %s\n", filename, strerror(errno));
        return;
    }

    char *base_filename = strrchr(resolved_path, '/');
    if (base_filename) {
        base_filename++;
    } else {
        base_filename = resolved_path;
    }

    int fd = open(resolved_path, O_RDONLY);
    if (fd < 0) {
        DBG_ERROR("Cannot open file %s: %s\n", resolved_path, strerror(errno));
        fprintf(stderr, "Error: Cannot open file '%s' for reading: %s\n", resolved_path, strerror(errno));
        return;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        DBG_ERROR("Cannot stat file: %s\n", strerror(errno));
        close(fd);
        return;
    }

    uint64_t total_size = st.st_size;
    DBG_INFO("File size: %lu bytes\n", total_size);

    struct TransferStats stats;
    transfer_init_stats(&stats, total_size);
    size_t total_chunks = (total_size + MAX_DATA_SIZE - 1) / MAX_DATA_SIZE;
    DBG_INFO("File will be sent in %zu chunks\n", total_chunks);

    Packet packet = {0};
    packet.start_marker = START_MARKER;
    SET_TYPE(packet.size_seq_type, PKT_BACKUP);
    SET_SIZE(packet.size_seq_type, strlen(base_filename) + 1 + sizeof(size_t));

    size_t max_filename_len = MAX_DATA_SIZE - sizeof(size_t) - 1;
    if (strlen(base_filename) >= max_filename_len) {
        DBG_ERROR("Filename too long (max %zu chars): %s\n", max_filename_len - 1, base_filename);
        fprintf(stderr, RED "Error: Filename exceeds maximum length\n" RESET);
        close(fd);
        return;
    }
    
    memset(packet.data, 0, MAX_DATA_SIZE);
    memcpy(packet.data, base_filename, strlen(base_filename));
    *((size_t *)(packet.data + strlen(base_filename) + 1)) = total_size;

    if (send_packet(socket, &packet, addr) < 0 ||
        wait_for_ack(socket, &packet, addr, PKT_ACK) != 0 ||
        wait_for_ack(socket, &packet, addr, PKT_OK_SIZE) != 0) {
        DBG_ERROR("Failed to initialize backup\n");
        close(fd);
        return;
    }

    char buffer[MAX_DATA_SIZE];
    uint16_t seq = 0;

    while (stats.total_received < total_size) {
        uint64_t to_read = total_size - stats.total_received;
        if (to_read > MAX_DATA_SIZE) {
            to_read = MAX_DATA_SIZE;
        }
        
        ssize_t bytes = read(fd, buffer, to_read);
        if (bytes <= 0) {
            DBG_ERROR("Read error: %s\n", strerror(errno));

            Packet error_packet = {0};
            error_packet.start_marker = START_MARKER;
            SET_TYPE(error_packet.size_seq_type, PKT_ERROR);
            SET_SIZE(error_packet.size_seq_type, 1);
            error_packet.data[0] = ERR_NO_ACCESS;
            send_packet(socket, &error_packet, addr);

            close(fd);
            return;
        }

        if (bytes > MAX_DATA_SIZE) {
            DBG_ERROR("Read more bytes than allowed: %zd\n", bytes);
            close(fd);
            return;
        }

        if (stats.total_received + bytes > total_size) {
            DBG_ERROR("Attempting to send more data than total size\n");
            close(fd);
            return;
        }

        if (seq > SEQ_MASK) {
            DBG_ERROR("Sequence number overflow\n");
            close(fd);
            return;
        }

        size_t remaining = total_size - stats.total_received;
        DBG_INFO("Preparing chunk: seq=%d, size=%zd, remaining=%zu\n",
                 seq, bytes, remaining);

        int retries = 0;
        bool chunk_sent = false;

        uint16_t current_seq = seq & SEQ_MASK;
        
        while (retries < MAX_RETRIES && !chunk_sent) {
            SET_TYPE(packet.size_seq_type, PKT_DATA);
            SET_SEQUENCE(packet.size_seq_type, current_seq);
            SET_SIZE(packet.size_seq_type, bytes & 0x3F);
            memcpy(packet.data, buffer, bytes);

            if (send_packet(socket, &packet, addr) >= 0) {
                if (wait_for_ack(socket, &packet, addr, PKT_OK) == 0) {
                    if (SEQ_DIFF(GET_SEQUENCE(packet.size_seq_type), current_seq) == 0) {
                        transfer_update_stats(&stats, bytes, current_seq);
                        seq = (current_seq + 1) & SEQ_MASK;
                        
                        if (seq == 0) {
                            transfer_handle_wrap(&stats);
                        }
                        
                        chunk_sent = true;
                        float progress = (float)(stats.total_received * 100.0) / total_size;
                        DBG_INFO("Progress: %.1f%% (%lu/%lu bytes, seq: %u, wraps: %u)\n",
                                progress, stats.total_received, total_size,
                                current_seq, stats.wrap_count);
                    }
                }
            }

            if (!chunk_sent) {
                retries++;
                DBG_WARN("Retrying chunk seq=%d (attempt %d/%d)\n",
                         seq, retries, MAX_RETRIES);
                usleep(RETRY_DELAY_MS * 1000);
                if (retries >= MAX_RETRIES) {
                    DBG_ERROR("Failed to send chunk after %d retries\n", MAX_RETRIES);
                    close(fd);
                    return;
                }
            } else {
                retries = 0;
            }
        }
    }

    if (stats.total_received == total_size) {
        DBG_INFO("All chunks sent successfully, sending END_TX\n");
        SET_TYPE(packet.size_seq_type, PKT_END_TX);
        SET_SIZE(packet.size_seq_type, 0);

        int retries = 0;
        bool end_tx_sent = false;
        while (retries < MAX_RETRIES && !end_tx_sent) {
            if (send_packet(socket, &packet, addr) >= 0 &&
                wait_for_ack(socket, &packet, addr, PKT_OK_CHSUM) == 0) {
                print_transfer_summary(&stats);
                DBG_INFO("Transfer completed successfully\n");
                end_tx_sent = true;
            } else {
                retries++;
                DBG_WARN("Retrying END_TX (attempt %d/%d)\n", retries, MAX_RETRIES);
                usleep(RETRY_DELAY_MS * 1000);
            }
        }

        if (!end_tx_sent) {
            DBG_ERROR("Failed to send END_TX after %d retries\n", MAX_RETRIES);
        }
    } else {
        DBG_ERROR("Transfer incomplete, not sending END_TX\n");
    }

    close(fd);
}

int restore_file(int socket, char *filename, struct sockaddr_ll *addr) {
    DBG_INFO("Starting restore of %s\n", filename);

    Packet packet = {0};
    packet.start_marker = START_MARKER;
    SET_TYPE(packet.size_seq_type, PKT_RESTORE);
    strncpy(packet.data, filename, MAX_DATA_SIZE - 1);
    packet.data[MAX_DATA_SIZE - 1] = '\0';
    SET_SIZE(packet.size_seq_type, strlen(packet.data));
    send_packet(socket, &packet, addr);

    if (receive_packet(socket, &packet, addr) > 0) {
        if (GET_TYPE(packet.size_seq_type) == PKT_ERROR) {
            if (packet.data[0] == ERR_NOT_FOUND) {
                fprintf(stderr, RED "Error: File '%s' not found in backup\n" RESET, filename);
            } else {
                fprintf(stderr, RED "Error: Server returned error code %d\n" RESET, packet.data[0]);
            }
            return 1;
        }
        
        if (GET_TYPE(packet.size_seq_type) == PKT_SIZE) {
            uint64_t total_size = *((uint64_t *)packet.data);
            DBG_INFO("File size to restore: %lu bytes\n", total_size);

            struct TransferStats stats;
            transfer_init_stats(&stats, total_size);

            int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd < 0) {
                DBG_ERROR("Cannot create file %s: %s\n", filename, strerror(errno));
                return 1;
            }

            uint16_t expected_seq = 0;

            while (stats.total_received < total_size) {
                if (receive_packet(socket, &packet, addr) <= 0) {
                    fprintf(stderr, "No response from server\n");
                    close(fd);
                    return 1;
                }
                debug_packet("RX", &packet);
                switch (GET_TYPE(packet.size_seq_type)) {
                    case PKT_DATA:
                        uint16_t recv_seq = GET_SEQUENCE(packet.size_seq_type);
                        if (SEQ_DIFF(recv_seq, expected_seq) != 0) {
                            fprintf(stderr, "Sequence mismatch: expected %d, got %d\n",
                                    expected_seq, recv_seq);
                            close(fd);
                            return 1;
                        }

                        if (write(fd, packet.data, GET_SIZE(packet.size_seq_type)) < 0) {
                            fprintf(stderr, "Write error\n");
                            close(fd);
                            return 1;
                        }

                        expected_seq = (recv_seq + 1) & SEQ_MASK;
                        transfer_update_stats(&stats, GET_SIZE(packet.size_seq_type), recv_seq);

                        float progress = (float)(stats.total_received * 100.0) / total_size;
                        DBG_INFO("Progress: %.1f%% (%lu/%lu bytes)\n",
                                 progress, stats.total_received, total_size);

                        Packet ack = {0};
                        ack.start_marker = START_MARKER;
                        SET_TYPE(ack.size_seq_type, PKT_OK);
                        SET_SEQUENCE(ack.size_seq_type, GET_SEQUENCE(packet.size_seq_type));
                        send_packet(socket, &ack, addr);
                        break;
                    case PKT_END_TX:
                        SET_TYPE(packet.size_seq_type, PKT_OK_CHSUM);
                        send_packet(socket, &packet, addr);
                        print_transfer_summary(&stats);
                        DBG_INFO("Transfer completed successfully\n");
                        close(fd);
                        return 0;
                    case PKT_ERROR:
                        if (packet.data[0] == ERR_NOT_FOUND) {
                            fprintf(stderr, "Error: File '%s' not found in server backup.\n", filename);
                        } else {
                            fprintf(stderr, "Error: Received error code %d\n", packet.data[0]);
                        }
                        close(fd);
                        return 1;
                    case PKT_NACK:
                        fprintf(stderr, "Transfer failed\n");
                        close(fd);
                        return 1;
                }
            }

            print_transfer_summary(&stats);
            DBG_INFO("Transfer completed successfully\n");
            close(fd);
            return 0;
        }
    }

    fprintf(stderr, RED "Error: No valid response from server\n" RESET);
    return 1;
}

void verify_file(int socket, char *filename, struct sockaddr_ll *addr) {
    DBG_INFO("Verifying %s\n", filename);

    Packet packet = {0};
    packet.start_marker = START_MARKER;
    SET_TYPE(packet.size_seq_type, PKT_VERIFY);
    strncpy(packet.data, filename, MAX_DATA_SIZE - 1);
    packet.data[MAX_DATA_SIZE - 1] = '\0';
    SET_SIZE(packet.size_seq_type, strlen(packet.data));
    send_packet(socket, &packet, addr);

    if (receive_packet(socket, &packet, addr) > 0) {
        if (GET_TYPE(packet.size_seq_type) == PKT_ACK) {
            printf("File exists in backup\n");
        } else if (GET_TYPE(packet.size_seq_type) == PKT_ERROR) {
            printf("File not found in backup\n");
        }
    } else {
        fprintf(stderr, "No response from server\n");
    }
}

int main(int argc, char *argv[]) {
    debug_init();

    if (argc == 2 && strcmp(argv[1], "-h") == 0) {
        display_help(argv[0]);
        return 0;
    }

    if (argc != 4) {
        fprintf(stderr, RED "Error: Invalid number of arguments\n" RESET);
        fprintf(stderr, "Use '%s -h' for help\n", argv[0]);
        exit(1);
    }

    int socket = cria_raw_socket(argv[1]);
    struct sockaddr_ll addr;
    if (get_interface_info(socket, argv[1], &addr) < 0) {
        exit(1);
    }

    unsigned char server_mac[ETH_ALEN];
    if (read_mac_from_config("config.cfg", server_mac) != 0) {
        fprintf(stderr, RED "Error: Failed to read MAC address from config file.\n" RESET);
        exit(1);
    }
    memcpy(addr.sll_addr, server_mac, ETH_ALEN);

    if (strcmp(argv[2], "backup") == 0) {
        backup_file(socket, argv[3], &addr);
    } else if (strcmp(argv[2], "restaura") == 0) {
        if (restore_file(socket, argv[3], &addr) != 0) {
            fprintf(stderr, "An error occurred during file restoration.\n");
            exit(1);
        }
    } else if (strcmp(argv[2], "verifica") == 0) {
        verify_file(socket, argv[3], &addr);
    } else {
        fprintf(stderr, "Invalid command\n");
        exit(1);
    }

    return 0;
}