/*
 * microtcp, a lightweight implementation of TCP for teaching,
 * and academic purposes.
 *
 * Copyright (C) 2015-2017  Manolis Surligas <surligas@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * You can use this file to write a test microTCP client.
 * This file is already inserted at the build system.
 */

#include "../lib/microtcp.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>

#include <stdlib.h>
#include <string.h>

int
main(int argc, char **argv)
{

	if (argc != 3) {
		printf("WRONG USE!\n");
		return -1;
	}

	struct sockaddr_in server_addr;
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(atoi(argv[2]));
	server_addr.sin_addr.s_addr = inet_addr(argv[1]);

	microtcp_sock_t socket = microtcp_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	printf("Client: connecting to server...\n");

	int ret = microtcp_connect(&socket, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in));

	if (ret) {
		printf("Client ERROR\n");
	}

	printf("Client: connection established\n");


	char *data = malloc(MICROTCP_MSS);

	for (int i = 0; i < 10; i++) {
		memset(data, i, MICROTCP_MSS);
		microtcp_send(&socket, data, MICROTCP_MSS, 0);
	}

	microtcp_shutdown(&socket, 0);

	printf("Client: connection shutdown\n");
}
