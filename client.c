#include "sockets.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>

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
    
    Packet packet = {0};
    packet.start_marker = START_MARKER;
    packet.proto_marker = PROTO_MARKER;
    packet.node_type = node_type;
    packet.type = PKT_BACKUP;
    strncpy(packet.data, filename, MAX_DATA_SIZE - 1);
    packet.data[MAX_DATA_SIZE - 1] = '\0';
    packet.length = strlen(packet.data);
    send_packet(socket, &packet, addr);
    
    // Wait for initial ACK
    if (receive_packet(socket, &packet, addr, NODE_CLIENT) <= 0 || 
        (packet.type & 0x1F) != PKT_ACK) {
        DBG_ERROR("Server did not acknowledge backup request\n");
        close(fd);
        return;
    }
    DBG_INFO("Received initial ACK\n");
    
    // Wait for size acknowledgment
    if (receive_packet(socket, &packet, addr, NODE_CLIENT) <= 0) {
        DBG_ERROR("No response for size acknowledgment\n");
        close(fd);
        return;
    }
    
    debug_packet("RX (Size Acknowledgment)", &packet);
    if ((packet.type & 0x1F) != PKT_OK_SIZE) {
        DBG_ERROR("Server did not acknowledge size (got type 0x%02x)\n", packet.type);
        close(fd);
        return;
    }
    DBG_INFO("Size acknowledged by server\n");

    char buffer[MAX_DATA_SIZE];
    ssize_t bytes;
    uint8_t seq = 0;
    size_t total_bytes = 0;
    
    set_socket_timeout(socket, SOCKET_TIMEOUT_MS);
    
    // Get file size for progress reporting
    struct stat st;
    if (fstat(fd, &st) == 0) {
        DBG_INFO("File size: %ld bytes\n", (long)st.st_size);
    }
    
    while ((bytes = read(fd, buffer, MAX_DATA_SIZE)) > 0) {
        total_bytes += bytes;
        DBG_INFO("Reading chunk: %zd bytes (total: %zu)\n", bytes, total_bytes);
        
        int retries = 0;
        while (retries < MAX_RETRIES) {
            packet.type = PKT_DATA;
            packet.sequence = seq;
            packet.length = bytes;
            memcpy(packet.data, buffer, bytes);
            
            DBG_INFO("Sending DATA packet: seq=%d, len=%zd\n", seq, bytes);
            if (send_packet(socket, &packet, addr) < 0) {
                DBG_ERROR("Send failed\n");
                retries++;
                continue;
            }
            
            if (wait_for_ack(socket, &packet, addr, PKT_OK, NODE_CLIENT) == 0) {
                seq = (seq + 1) & SEQ_MASK;
                break;
            }
            
            retries++;
            DBG_WARN("Retrying packet %d (attempt %d)\n", seq, retries);
            usleep(RETRY_DELAY_MS * 1000);  // Add delay between retries
        }
        
        if (retries >= MAX_RETRIES) {
            DBG_ERROR("Max retries reached, transfer failed\n");
            close(fd);
            return;
        }
    }

    if (bytes < 0) {
        DBG_ERROR("Read error: %s\n", strerror(errno));
        close(fd);
        return;
    }

    DBG_INFO("File transfer complete: %zu bytes sent\n", total_bytes);
    
    // Send end of transmission
    packet.type = PKT_END_TX;
    send_packet(socket, &packet, addr);
    
    // Wait for checksum acknowledgment
    if (receive_packet(socket, &packet, addr, NODE_CLIENT) > 0 && 
        (packet.type & 0x1F) == PKT_OK_CHSUM) {
        printf("Transfer completed successfully\n");
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
