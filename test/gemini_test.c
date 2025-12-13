


#include "../lib/microtcp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>


int
main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <server-ip> <server-port>\n", argv[0]);
        return 1;
    }

    const char *server_ip = argv[1];
    int server_port = atoi(argv[2]);

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(server_port);
    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) != 1) {
        perror("inet_pton");
        return 1;
    }

    microtcp_sock_t sock = microtcp_socket(AF_INET, SOCK_DGRAM, 0);

    if (microtcp_connect(&sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == 0) {
        printf("microtcp: handshake succeeded, state = %d\n", sock.state);
        /* Optionally shutdown cleanly */
        microtcp_shutdown(&sock, 0);
        return 0;
    } else {
        fprintf(stderr, "microtcp: handshake failed\n");
        return 1;
    }
}