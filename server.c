#include "sockets.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <limits.h>

#define BACKUP_DIR "./backup/"

void handle_backup(int socket, Packet *packet);
void handle_restore(int socket, Packet *packet);
void handle_verify(int socket, Packet *packet);
void handle_data_packet(int socket, Packet *packet, int fd, struct sockaddr_ll *addr);

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        exit(1);
    }

    int socket = cria_raw_socket(argv[1]);
    Packet packet;
    mkdir(BACKUP_DIR, 0777);

    while (1) {
        if (receive_packet(socket, &packet) > 0) {
            switch (packet.type & 0x1F) {
                case PKT_BACKUP:
                    handle_backup(socket, &packet);
                    break;
                case PKT_DATA:
                    // Handle incoming data
                    break;
                case PKT_END_TX:
                    // Handle end of transmission
                    break;
                case PKT_RESTORE:
                    handle_restore(socket, &packet);
                    break;
                case PKT_VERIFY:
                    handle_verify(socket, &packet);
                    break;
            }
        }
    }

    return 0;
}

void handle_data_packet(int socket, Packet *packet, int fd, struct sockaddr_ll *addr) {
    static uint8_t expected_seq = 0;
    
    if (packet->sequence != expected_seq) {
        debug_print("Wrong sequence number, expected %d got %d\n", 
                   expected_seq, packet->sequence);
        send_error(socket, addr, ERR_SEQUENCE);
        return;
    }
    
    if (write(fd, packet->data, packet->length & 0x3F) < 0) {
        debug_print("Write failed\n");
        send_error(socket, addr, ERR_NO_SPACE);
        return;
    }
    
    expected_seq = (expected_seq + 1) & 0x1F;
    Packet response = {0};
    response.type = PKT_OK;
    send_packet(socket, &response, addr);
}

void handle_backup(int socket, Packet *packet) {
    debug_print("Starting backup for file: %s\n", packet->data);
    char filepath[PATH_MAX];
    
    snprintf(filepath, sizeof(filepath), "%s%s", BACKUP_DIR, packet->data);
    
    int fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        send_error(socket, &g_socket_addr, ERR_NO_ACCESS);
        return;
    }
    
    // Send acknowledgement
    send_ack(socket, &g_socket_addr, PKT_ACK);
    
    // Send OK + Size response
    Packet response = {0};
    response.type = PKT_OK_SIZE;
    send_packet(socket, &response, &g_socket_addr);
    
    while (1) {
        if (receive_packet(socket, packet) <= 0) {
            debug_print("Receive timeout\n");
            send_error(socket, &g_socket_addr, ERR_TIMEOUT);
            break;
        }
        
        switch (packet->type & 0x1F) {
            case PKT_DATA:
                handle_data_packet(socket, packet, fd, &g_socket_addr);
                break;
            case PKT_END_TX:
                debug_print("End of transmission received\n");
                response.type = PKT_OK_CHSUM;
                send_packet(socket, &response, &g_socket_addr);
                close(fd);
                return;
            default:
                debug_print("Unexpected packet type: 0x%02x\n", packet->type);
                send_error(socket, &g_socket_addr, ERR_SEQUENCE);
                break;
        }
    }
    close(fd);
}

void handle_restore(int socket, Packet *packet) {
    debug_print("Starting restore for file: %s\n", packet->data);
    char filepath[PATH_MAX];
    
    snprintf(filepath, sizeof(filepath), "%s%s", BACKUP_DIR, packet->data);
    
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        send_error(socket, &g_socket_addr, ERR_NOT_FOUND);
        return;
    }
    
    char buffer[MAX_DATA_SIZE];
    ssize_t bytes;
    uint8_t seq = 0;
    
    while ((bytes = read(fd, buffer, MAX_DATA_SIZE)) > 0) {
        debug_print("Sending restore chunk: %zd bytes\n", bytes);
        Packet data = {0};
        data.type = PKT_DATA;
        data.sequence = seq++;
        data.length = bytes;
        memcpy(data.data, buffer, bytes);
        send_packet(socket, &data, &g_socket_addr);
    }
    
    close(fd);
}

void handle_verify(int socket, Packet *packet) {
    debug_print("Verifying file: %s\n", packet->data);
    char filepath[PATH_MAX];
    
    snprintf(filepath, sizeof(filepath), "%s%s", BACKUP_DIR, packet->data);
    
    struct stat st;
    if (stat(filepath, &st) == 0) {
        send_ack(socket, &g_socket_addr, PKT_ACK);
    } else {
        send_error(socket, &g_socket_addr, ERR_NOT_FOUND);
    }
}
