#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define DEFAULT_PORT 5001
#define EXPECTED_CHUNK_SIZE 1024
#define DEFAULT_TRANSFERS 10

static volatile int g_running = 1;

static void handle_sigint(int sig) {
    (void)sig;
    g_running = 0;
}

int main(int argc, char **argv) {
    uint16_t port = DEFAULT_PORT;
    const char *bind_ip = "0.0.0.0";
    int run_once = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-p") || !strcmp(argv[i], "--port")) {
            if (++i < argc) port = (uint16_t)atoi(argv[i]);
        } else if (!strcmp(argv[i], "-b") || !strcmp(argv[i], "--bind")) {
            if (++i < argc) bind_ip = argv[i];
        } else if (!strcmp(argv[i], "-o") || !strcmp(argv[i], "--once")) {
            run_once = 1;
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            printf("Usage: %s [options]\n", argv[0]);
            printf("  -p, --port PORT     Port to listen on (default: %u)\n", DEFAULT_PORT);
            printf("  -b, --bind IP       IP to bind to (default: %s)\n", bind_ip);
            printf("  -o, --once          Exit after handling one client session\n");
            printf("  -h, --help          Show this help message\n");
            return 0;
        }
    }

    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("[Server] socket");
        return 1;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(bind_ip);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[Server] bind");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 5) < 0) {
        perror("[Server] listen");
        close(server_fd);
        return 1;
    }

    printf("=========================================================\n");
    printf("   SPEEDTEST SERVER (Pure C TCP Opposing Endpoint)       \n");
    printf("   Listening on %s:%u (Ctrl+C to stop)                   \n", bind_ip, port);
    printf("=========================================================\n");
    fflush(stdout);

    while (g_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (!g_running) break;
            perror("[Server] accept");
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        uint16_t client_port = ntohs(client_addr.sin_port);

        printf("\n[Server] Connected client: %s:%u\n", client_ip, client_port);
        fflush(stdout);

        uint8_t buffer[EXPECTED_CHUNK_SIZE];
        int transfer_count = 0;
        size_t total_bytes_received = 0;

        while (g_running) {
            size_t bytes_this_chunk = 0;

            /* Read until we have 1024 bytes (or client closes connection) */
            while (bytes_this_chunk < EXPECTED_CHUNK_SIZE) {
                ssize_t n = recv(client_fd, buffer + bytes_this_chunk,
                                 EXPECTED_CHUNK_SIZE - bytes_this_chunk, 0);
                if (n <= 0) {
                    /* Client closed connection (FIN) or error */
                    goto client_closed;
                }
                bytes_this_chunk += (size_t)n;
            }

            transfer_count++;
            total_bytes_received += bytes_this_chunk;

            printf("[Server] File Transfer %2d: received %zu bytes -> sending ACK\n",
                   transfer_count, bytes_this_chunk);
            fflush(stdout);

            /* Send acknowledgment confirmation to client */
            const char ack_reply[] = "ACK\n";
            ssize_t sent = send(client_fd, ack_reply, strlen(ack_reply), 0);
            if (sent < 0) {
                perror("[Server] send ACK failed");
                break;
            }

            if (transfer_count >= DEFAULT_TRANSFERS) {
                /* We have received the expected 10 transfers, wait for client FIN */
            }
        }

client_closed:
        printf("[Server] Disconnected client: %s:%u | Total transfers: %d (%zu bytes)\n",
               client_ip, client_port, transfer_count, total_bytes_received);
        fflush(stdout);
        close(client_fd);

        if (run_once) {
            printf("[Server] Single-session mode completed. Exiting.\n");
            break;
        }
    }

    close(server_fd);
    printf("[Server] Server stopped cleanly.\n");
    return 0;
}
