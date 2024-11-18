#include "sockets.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>

void backup_file(int socket, char *filename);
void restore_file(int socket, char *filename);
void verify_file(int socket, char *filename);

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <interface> <command> <filename>\n", argv[0]);
        exit(1);
    }

    int socket = cria_raw_socket(argv[1]);
    
    if (strcmp(argv[2], "backup") == 0) {
        backup_file(socket, argv[3]);
    } else if (strcmp(argv[2], "restaura") == 0) {
        restore_file(socket, argv[3]);
    } else if (strcmp(argv[2], "verifica") == 0) {
        verify_file(socket, argv[3]);
    } else {
        fprintf(stderr, "Invalid command\n");
        exit(1);
    }

    return 0;
}

void backup_file(int socket, char *filename) {
    debug_print("Starting backup of %s\n", filename);
    
    // Use global socket address
    struct sockaddr_ll *addr = &g_socket_addr;

    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Cannot open file %s\n", filename);
        return;
    }
    
    Packet packet = {0};
    packet.type = PKT_BACKUP;
    strncpy(packet.data, filename, MAX_DATA_SIZE - 1);
    packet.data[MAX_DATA_SIZE - 1] = '\0';
    packet.length = strlen(packet.data);
    send_packet(socket, &packet, addr);
    
    // Wait for size acknowledgment
    if (receive_packet(socket, &packet) <= 0 || 
        (packet.type & 0x1F) != PKT_OK_SIZE) {
        fprintf(stderr, "Server did not acknowledge size\n");
        return;
    }
    
    char buffer[MAX_DATA_SIZE];
    ssize_t bytes;
    uint8_t seq = 0;
    
    set_socket_timeout(socket, SOCKET_TIMEOUT_MS);
    
    while ((bytes = read(fd, buffer, MAX_DATA_SIZE)) > 0) {
        int retries = 0;
        while (retries < MAX_RETRIES) {
            packet.type = PKT_DATA;
            packet.sequence = seq;
            packet.length = bytes;
            memcpy(packet.data, buffer, bytes);
            
            if (send_packet(socket, &packet, addr) < 0) {
                debug_print("Send failed\n");
                retries++;
                continue;
            }
            
            if (wait_for_ack(socket, &packet, PKT_OK) == 0) {
                seq = (seq + 1) & 0x1F;
                break;
            }
            
            retries++;
            debug_print("Retrying packet %d (attempt %d)\n", seq, retries);
        }
        
        if (retries >= MAX_RETRIES) {
            fprintf(stderr, "Max retries reached, transfer failed\n");
            close(fd);
            return;
        }
    }
    
    // Send end of transmission
    packet.type = PKT_END_TX;
    send_packet(socket, &packet, addr);
    
    // Wait for checksum acknowledgment
    if (receive_packet(socket, &packet) > 0 && 
        (packet.type & 0x1F) == PKT_OK_CHSUM) {
        printf("Transfer completed successfully\n");
    }
    
    close(fd);
}

void restore_file(int socket, char *filename) {
    debug_print("Starting restore of %s\n", filename);
    
    // Use global socket address
    struct sockaddr_ll *addr = &g_socket_addr;

    Packet packet = {0};
    packet.type = PKT_RESTORE;
    strncpy(packet.data, filename, MAX_DATA_SIZE - 1);
    packet.data[MAX_DATA_SIZE - 1] = '\0';
    packet.length = strlen(packet.data);
    send_packet(socket, &packet, addr);
    
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        fprintf(stderr, "Cannot create file %s\n", filename);
        return;
    }
    
    while (receive_packet(socket, &packet) > 0) {
        debug_print("Received packet type: 0x%02x\n", packet.type);
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

void verify_file(int socket, char *filename) {
    debug_print("Verifying %s\n", filename);
    
    // Use global socket address
    struct sockaddr_ll *addr = &g_socket_addr;

    Packet packet = {0};
    packet.type = PKT_VERIFY;
    strncpy(packet.data, filename, MAX_DATA_SIZE - 1);
    packet.data[MAX_DATA_SIZE - 1] = '\0';
    packet.length = strlen(packet.data);
    send_packet(socket, &packet, addr);
    
    if (receive_packet(socket, &packet) > 0) {
        if ((packet.type & 0x1F) == PKT_ACK) {
            printf("File exists in backup\n");
        } else if ((packet.type & 0x1F) == PKT_ERROR) {
            printf("File not found in backup\n");
        }
    }
}
