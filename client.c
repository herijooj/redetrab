#include "sockets.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <ctype.h>

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_RESET   "\x1b[0m"

void backup_file(int socket, char *filename, struct sockaddr_ll *addr);
int restore_file(int socket, char *filename, struct sockaddr_ll *addr);
void verify_file(int socket, char *filename, struct sockaddr_ll *addr);

void display_help(const char* program_name) {
    printf(ANSI_COLOR_BLUE "NARBS Client (Not A Real Backup Solution)\n" ANSI_COLOR_RESET);

    printf(ANSI_COLOR_GREEN "Usage:\n" ANSI_COLOR_RESET);
    printf("  %s <interface> <command> <filename>\n\n", program_name);

    printf(ANSI_COLOR_YELLOW "Commands:\n" ANSI_COLOR_RESET);
    printf("  backup    - Create a backup of a file\n");
    printf("  restaura  - Restore a file from backup\n");
    printf("  verifica - Verify if a file exists in backup\n\n");

    printf(ANSI_COLOR_YELLOW "Options:\n" ANSI_COLOR_RESET);
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

int main(int argc, char *argv[]) {
    debug_init();  // Initialize debug system

    if (argc == 2 && strcmp(argv[1], "-h") == 0) {
        display_help(argv[0]);
        return 0;
    }

    if (argc != 4) {
        fprintf(stderr, ANSI_COLOR_RED "Error: Invalid number of arguments\n" ANSI_COLOR_RESET);
        fprintf(stderr, "Use '%s -h' for help\n", argv[0]);
        exit(1);
    }

    int socket = cria_raw_socket(argv[1]);
    struct sockaddr_ll addr;
    if (get_interface_info(socket, argv[1], &addr) < 0) {
        exit(1);
    }

    // Replace hardcoded MAC with config reading
    unsigned char server_mac[ETH_ALEN];
    if (read_mac_from_config("config.cfg", server_mac) != 0) {
        fprintf(stderr, ANSI_COLOR_RED "Error: Failed to read MAC address from config file.\n" ANSI_COLOR_RESET);
        exit(1);
    }
    memcpy(addr.sll_addr, server_mac, ETH_ALEN);

    if (strcmp(argv[2], "backup") == 0) {
        backup_file(socket, argv[3], &addr);
    } else if (strcmp(argv[2], "restaura") == 0) {
        if (restore_file(socket, argv[3], &addr) != 0) {
            fprintf(stderr, "An error occurred during file restoration.\n");
            exit(1); // Exit gracefully on error
        }
    } else if (strcmp(argv[2], "verifica") == 0) {
        verify_file(socket, argv[3], &addr);
    } else {
        fprintf(stderr, "Invalid command\n");
        exit(1);
    }

    return 0;
}

void backup_file(int socket, char *filename, struct sockaddr_ll *addr) {
    DBG_INFO("Starting backup of %s\n", filename);

    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        DBG_ERROR("Cannot open file %s: %s\n", filename, strerror(errno));
        fprintf(stderr, "Error: Cannot open file '%s' for reading: %s\n", filename, strerror(errno));
        return;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        DBG_ERROR("Cannot stat file: %s\n", strerror(errno));
        close(fd);
        return;
    }

    size_t total_size = st.st_size;
    DBG_INFO("File size: %ld bytes\n", (long)total_size);

    struct TransferStats stats;
    transfer_init_stats(&stats, total_size);
    size_t total_chunks = (total_size + MAX_DATA_SIZE - 1) / MAX_DATA_SIZE;
    DBG_INFO("File will be sent in %zu chunks\n", total_chunks);

    // Send initial backup packet with file info
    Packet packet = {0};
    packet.start_marker = START_MARKER;
    packet.type = PKT_BACKUP;

    // Pack filename and size
    strncpy(packet.data, filename, MAX_DATA_SIZE - sizeof(size_t) - 1);
    *((size_t *)(packet.data + strlen(filename) + 1)) = total_size;
    packet.length = strlen(filename) + 1 + sizeof(size_t);

    if (send_packet(socket, &packet, addr) < 0 ||
        wait_for_ack(socket, &packet, addr, PKT_ACK) != 0 ||
        wait_for_ack(socket, &packet, addr, PKT_OK_SIZE) != 0) {
        DBG_ERROR("Failed to initialize backup\n");
        close(fd);
        return;
    }

    // Transfer file data
    char buffer[MAX_DATA_SIZE];
    uint8_t seq = 0;

    while (stats.total_received < total_size) {
        ssize_t bytes = read(fd, buffer, MAX_DATA_SIZE);
        if (bytes <= 0) {
            DBG_ERROR("Read error: %s\n", strerror(errno));

            // Send an error packet to the server
            Packet error_packet = {0};
            error_packet.start_marker = START_MARKER;
            error_packet.type = PKT_ERROR;
            error_packet.length = 1;
            error_packet.data[0] = ERR_NO_ACCESS; // Or appropriate error code
            send_packet(socket, &error_packet, addr);

            close(fd);
            return;
        }

        // Validate bytes read
        if (bytes > MAX_DATA_SIZE) {
            DBG_ERROR("Read more bytes than allowed: %zd\n", bytes);
            close(fd);
            return;
        }

        // Ensure not exceeding total_size
        if (stats.total_received + bytes > total_size) {
            DBG_ERROR("Attempting to send more data than total size\n");
            close(fd);
            return;
        }

        size_t remaining = total_size - stats.total_received;
        DBG_INFO("Preparing chunk: seq=%d, size=%zd, remaining=%zu\n",
                 seq, bytes, remaining);

        int retries = 0;
        bool chunk_sent = false;

        while (retries < MAX_RETRIES && !chunk_sent) {
            packet.type = PKT_DATA;
            packet.sequence = seq;
            packet.length = bytes;
            memcpy(packet.data, buffer, bytes);

            if (send_packet(socket, &packet, addr) >= 0) {
                if (wait_for_ack(socket, &packet, addr, PKT_OK) == 0) {
                    transfer_update_stats(&stats, bytes, seq);
                    seq = (seq + 1) & SEQ_MASK;
                    chunk_sent = true;

                    float progress = (float)stats.total_received / total_size * 100;
                    DBG_INFO("Progress: %.1f%% (%zu/%zu bytes)\n",
                             progress, stats.total_received, total_size);
                } else {
                    DBG_WARN("No ACK received for seq %d\n", seq);
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
                    return;  // Exit without sending PKT_END_TX
                }
            } else {
                retries = 0;  // Reset retries after a successful send
            }
        }
    }
    // Only send PKT_END_TX if all data was sent successfully
    if (stats.total_received == total_size) {
        DBG_INFO("All chunks sent successfully, sending END_TX\n");
        packet.type = PKT_END_TX;
        packet.length = 0;

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
    packet.type = PKT_RESTORE;
    strncpy(packet.data, filename, MAX_DATA_SIZE - 1);
    packet.data[MAX_DATA_SIZE - 1] = '\0';
    packet.length = strlen(packet.data);
    send_packet(socket, &packet, addr);

    // Receive the file size from the server
    if (receive_packet(socket, &packet, addr) > 0 && packet.type == PKT_SIZE) {  // Changed from PKT_FILE_SIZE to PKT_SIZE
        size_t total_size = *((size_t *)packet.data);
        DBG_INFO("File size to restore: %zu bytes\n", total_size);

        struct TransferStats stats;
        transfer_init_stats(&stats, total_size);

        int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            DBG_ERROR("Cannot create file %s: %s\n", filename, strerror(errno));
            return 1; // Return non-zero on error
        }

        while (stats.total_received < total_size) {
            if (receive_packet(socket, &packet, addr) <= 0) {
                fprintf(stderr, "No response from server\n");
                close(fd);
                return 1;
            }
            debug_packet("RX", &packet);
            switch (packet.type & TYPE_MASK) {
                case PKT_DATA:
                    if (write(fd, packet.data, packet.length & LEN_MASK) < 0) {
                        fprintf(stderr, "Write error\n");
                        close(fd);
                        return 1; // Return error code
                    }
                    transfer_update_stats(&stats, packet.length & LEN_MASK, packet.sequence);

                    float progress = (float)stats.total_received / total_size * 100;
                    DBG_INFO("Progress: %.1f%% (%zu/%zu bytes)\n",
                             progress, stats.total_received, total_size);

                    // Send ACK for the received packet
                    Packet ack = {0};
                    ack.start_marker = START_MARKER;
                    ack.type = PKT_OK;
                    ack.sequence = packet.sequence & SEQ_MASK;
                    send_packet(socket, &ack, addr);
                    break;
                case PKT_END_TX:
                    packet.type = PKT_OK_CHSUM;
                    send_packet(socket, &packet, addr);
                    print_transfer_summary(&stats);
                    DBG_INFO("Transfer completed successfully\n");
                    close(fd);
                    return 0; // Return 0 on success
                case PKT_ERROR:
                    if (packet.data[0] == ERR_NOT_FOUND) {
                        fprintf(stderr, "Error: File '%s' not found in server backup.\n", filename);
                    } else {
                        fprintf(stderr, "Error: Received error code %d\n", packet.data[0]);
                    }
                    close(fd);
                    return 1; // Return error code
                case PKT_NACK:
                    fprintf(stderr, "Transfer failed\n");
                    close(fd);
                    return 1; // Return error code
            }
        }

        // If the transfer completes without receiving END_TX
        print_transfer_summary(&stats);
        DBG_INFO("Transfer completed successfully\n");
        close(fd);
        return 0;
    } else {
        fprintf(stderr, "Failed to receive file size from server\n");
        return 1;
    }
}

void verify_file(int socket, char *filename, struct sockaddr_ll *addr) {
    DBG_INFO("Verifying %s\n", filename);

    Packet packet = {0};
    packet.start_marker = START_MARKER;
    packet.type = PKT_VERIFY;
    strncpy(packet.data, filename, MAX_DATA_SIZE - 1);
    packet.data[MAX_DATA_SIZE - 1] = '\0';
    packet.length = strlen(packet.data);
    send_packet(socket, &packet, addr);

    if (receive_packet(socket, &packet, addr) > 0) {
        if ((packet.type & TYPE_MASK) == PKT_ACK) {
            printf("File exists in backup\n");
        } else if ((packet.type & TYPE_MASK) == PKT_ERROR) {
            printf("File not found in backup\n");
        }
    } else {
        fprintf(stderr, "No response from server\n");
    }
}
