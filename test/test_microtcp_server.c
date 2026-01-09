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
 * You can use this file to write a test microTCP server.
 * This file is already inserted at the build system.
 */


#include "../lib/microtcp.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>

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

	microtcp_bind(&socket, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in));

	struct sockaddr client_addr;


	printf("Server: waiting for incoming connection...\n");

	int ret = microtcp_accept(&socket, &client_addr, sizeof(struct sockaddr));

	if (ret) {
		printf("Server ERROR\n");
	}

	printf("Server: connection established\n");

	char *data = malloc(MICROTCP_MSS + sizeof(microtcp_header_t));

	microtcp_header_t* rec_header; // = { 0 };
	do {
		// recv(socket.sd, data, MICROTCP_MSS + sizeof(microtcp_header_t), 0);
		microtcp_recv(&socket, data, MICROTCP_MSS + sizeof(microtcp_header_t), 0);
		rec_header = (microtcp_header_t*)data;
		printf("data: %u\n", (int)data[sizeof(microtcp_header_t)]);
/*		header_to_net(&rec_header);
		printf("Received header:\n");
		print_header(&rec_header);*/
	} while(!(rec_header->control & 1));

	socket.state = CLOSING_BY_PEER;
	microtcp_shutdown(&socket, 0);

	printf("Server: connetion shutdown\n");
}
