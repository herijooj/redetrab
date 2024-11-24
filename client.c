#include "sockets.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>

// Update function prototypes to include node_type
void backup_file(int socket, char *filename, struct sockaddr_ll *addr, int node_type);
void restore_file(int socket, char *filename, struct sockaddr_ll *addr, int node_type);
void verify_file(int socket, char *filename, struct sockaddr_ll *addr, int node_type);

int main(int argc, char *argv[]) {
    debug_init();  // Initialize debug system
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <interface> <command> <filename>\n", argv[0]);
        exit(1);
    }

    int socket = cria_raw_socket(argv[1]);
    int local_node_type = NODE_CLIENT;  // Keep this as we use it in packet node_type
    struct sockaddr_ll addr;
    if (get_interface_info(socket, argv[1], &addr) < 0) {
        exit(1);
    }
    
    // Get server's MAC address (veth0's MAC address)
    unsigned char server_mac[ETH_ALEN] = {0xd6, 0xb5, 0xc2, 0xee, 0x74, 0x85};
    memcpy(addr.sll_addr, server_mac, ETH_ALEN);
    
    if (strcmp(argv[2], "backup") == 0) {
        backup_file(socket, argv[3], &addr, local_node_type);
    } else if (strcmp(argv[2], "restaura") == 0) {
        restore_file(socket, argv[3], &addr, local_node_type);
    } else if (strcmp(argv[2], "verifica") == 0) {
        verify_file(socket, argv[3], &addr, local_node_type);
    } else {
        fprintf(stderr, "Invalid command\n");
        exit(1);
    }

    return 0;
}

void backup_file(int socket, char *filename, struct sockaddr_ll *addr, int node_type) {
    DBG_INFO("Starting backup of %s\n", filename);

    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        DBG_ERROR("Cannot open file %s: %s\n", filename, strerror(errno));
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
    init_transfer_stats(&stats, total_size);
    
    // Calculate total chunks
    size_t total_chunks = (total_size + MAX_DATA_SIZE - 1) / MAX_DATA_SIZE;
    DBG_INFO("File will be sent in %zu chunks\n", total_chunks);

    // Send initial backup packet with file info
    Packet packet = {0};
    packet.start_marker = START_MARKER;
    packet.proto_marker = PROTO_MARKER;
    packet.node_type = node_type;
    packet.type = PKT_BACKUP;
    
    // Pack filename and size
    strncpy(packet.data, filename, MAX_DATA_SIZE - sizeof(size_t) - 1);
    *((size_t *)(packet.data + strlen(filename) + 1)) = total_size;
    packet.length = strlen(filename) + 1 + sizeof(size_t);

    if (send_packet(socket, &packet, addr) < 0 ||
        wait_for_ack(socket, &packet, addr, PKT_ACK, NODE_CLIENT) != 0 ||
        wait_for_ack(socket, &packet, addr, PKT_OK_SIZE, NODE_CLIENT) != 0) {
        DBG_ERROR("Failed to initialize backup\n");
        close(fd);
        return;
    }

    // Transfer file data with improved logging and validation
    char buffer[MAX_DATA_SIZE];
    uint8_t seq = 0;
    
    while (stats.total_received < total_size) {
        ssize_t bytes = read(fd, buffer, MAX_DATA_SIZE);
        if (bytes <= 0) {
            DBG_ERROR("Read error or EOF: %s\n", strerror(errno));
            break;
        }

        size_t remaining = total_size - stats.total_received;
        DBG_INFO("Preparing chunk: seq=%d, size=%zd, remaining=%zu\n",
                 seq, bytes, remaining);

        int retries = 0;
        bool chunk_sent = false;
        
        while (retries < MAX_RETRIES && !chunk_sent) {
            packet.type = PKT_DATA;
            packet.sequence = seq;
            packet.length = bytes; // Updated to use 16-bit
            memcpy(packet.data, buffer, bytes);
            
            if (send_packet(socket, &packet, addr) >= 0) {
                if (wait_for_ack(socket, &packet, addr, PKT_OK, NODE_CLIENT) == 0) {
                    update_transfer_stats(&stats, bytes, seq);
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
            }
        }
        
        if (!chunk_sent) {
            DBG_ERROR("Failed to send chunk after %d retries\n", MAX_RETRIES);
            close(fd);
            return;
        }
    }
    // Verify all data was sent before END_TX
    if (stats.total_received == total_size) {
        DBG_INFO("All chunks sent successfully, sending END_TX\n");
        packet.type = PKT_END_TX;
        packet.length = 0;
        
        // Retry END_TX if needed
        int retries = 0;
        while (retries < MAX_RETRIES) {
            if (send_packet(socket, &packet, addr) >= 0 &&
                wait_for_ack(socket, &packet, addr, PKT_OK_CHSUM, NODE_CLIENT) == 0) {
                print_transfer_summary(&stats);
                DBG_INFO("Transfer completed successfully\n");
                break;
            }
            retries++;
            DBG_WARN("Retrying END_TX (attempt %d/%d)\n", retries, MAX_RETRIES);
            usleep(RETRY_DELAY_MS * 1000);
        }
    } else {
        DBG_ERROR("Transfer incomplete: sent %zu/%zu bytes\n", 
                  stats.total_received, total_size);
    }
    
    close(fd);
}

void restore_file(int socket, char *filename, struct sockaddr_ll *addr, int node_type) {
    DBG_INFO("Starting restore of %s\n", filename);

    Packet packet = {0};
    packet.start_marker = START_MARKER;
    packet.proto_marker = PROTO_MARKER;
    packet.node_type = node_type;
    packet.type = PKT_RESTORE;
    strncpy(packet.data, filename, MAX_DATA_SIZE - 1);
    packet.data[MAX_DATA_SIZE - 1] = '\0';
    packet.length = strlen(packet.data);
    send_packet(socket, &packet, addr);
    
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        DBG_ERROR("Cannot create file %s: %s\n", filename, strerror(errno));
        return;
    }
    
    while (receive_packet(socket, &packet, addr, NODE_CLIENT) > 0) {
        debug_packet("RX", &packet);
        switch (packet.type & 0x1F) {
            case PKT_DATA:
                if (write(fd, packet.data, packet.length & 0x3F) < 0) {
                    fprintf(stderr, "Write error\n");
                    close(fd);
                    return;
                }
                break;
            case PKT_END_TX:
                // Send checksum acknowledgment
                packet.type = PKT_OK_CHSUM;
                send_packet(socket, &packet, addr);
                return;
            case PKT_ERROR:
                fprintf(stderr, "Error: %d\n", packet.data[0]);
                return;
            case PKT_NACK:
                fprintf(stderr, "Transfer failed\n");
                return;
        }
    }
    
    close(fd);
}

void verify_file(int socket, char *filename, struct sockaddr_ll *addr, int node_type) {
    DBG_INFO("Verifying %s\n", filename);

    Packet packet = {0};
    packet.start_marker = START_MARKER;
    packet.proto_marker = PROTO_MARKER;
    packet.node_type = node_type;
    packet.type = PKT_VERIFY;
    strncpy(packet.data, filename, MAX_DATA_SIZE - 1);
    packet.data[MAX_DATA_SIZE - 1] = '\0';
    packet.length = strlen(packet.data);
    send_packet(socket, &packet, addr);
    
    if (receive_packet(socket, &packet, addr, NODE_CLIENT) > 0) {
        if ((packet.type & 0x1F) == PKT_ACK) {
            printf("File exists in backup\n");
        } else if ((packet.type & 0x1F) == PKT_ERROR) {
            printf("File not found in backup\n");
        }
    } else {
        fprintf(stderr, "No response from server\n");
    }
}
