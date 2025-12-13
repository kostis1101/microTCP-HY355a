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

#include "microtcp.h"
#include "../utils/crc32.h"
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>

microtcp_sock_t
microtcp_socket (int domain, int type, int protocol)
{
	int sock;

	if ((sock = socket(domain, type, protocol)) == -1) {
		perror( " SOCKET COULD NOT BE OPENED " );
		exit( EXIT_FAILURE );
	}

	microtcp_sock_t socket = { 0 };

	socket.sd = sock;
	socket.state = INVALID;

	return socket;
}

int
microtcp_bind (microtcp_sock_t *socket, const struct sockaddr *address,
							 socklen_t address_len)
{
	int res;
	if ((res = bind(socket->sd, address, address_len)) == -1) {
		perror("TCP error");
		exit(EXIT_FAILURE);
	}
	return res;
}

int
microtcp_connect (microtcp_sock_t *socket, const struct sockaddr *address,
									socklen_t address_len)
{
	microtcp_header_t header = { 0 };
	header.seq_number = 0;
	header.ack_number = 0;
	header.control = 1 << 1;

	header.checksum = crc32((uint8_t*)(void*)&header, sizeof(microtcp_header_t));

	ssize_t s = sendto(socket->sd, &header, sizeof(header), 0, address, address_len);
	if (s != sizeof(header)) {
		socket->state = INVALID;
		return -1;
	}

	socket->state = LISTEN;

	microtcp_header_t ret;

	s = recvfrom(socket->sd, &ret, sizeof(microtcp_header_t), 0, address, &address_len);
	uint32_t rcs = ret.checksum;
	ret.checksum = 0;
	uint32_t cs = crc32((uint8_t*)&ret, sizeof(microtcp_header_t));

	if (s != sizeof(microtcp_header_t) || ret.control != 10 || cs != rcs) {
		socket->state = INVALID;
		return -1;
	}

	microtcp_header_t header2 = { 0 };
	header2.seq_number = ret.ack_number;
	header2.ack_number = ret.seq_number + 1;
	header2.control = 8;

	header2.checksum = crc32((uint8_t*)&header2, sizeof(microtcp_header_t));

	s = sendto(socket->sd, &header2, sizeof(header2), 0, address, address_len);
	if (s != sizeof(header2)) {
		socket->state = INVALID;
		return -1;
	}

	socket->state = ESTABLISHED;

	return 0;
}

int
microtcp_accept (microtcp_sock_t *socket, struct sockaddr *address,
								 socklen_t address_len)
{
	microtcp_header_t client_rec;

	ssize_t s = recvfrom(socket->sd, &client_rec, sizeof(client_rec), 0, address, &address_len);
	uint32_t rcs = client_rec.checksum;
	client_rec.checksum = 0;
	uint32_t cs = crc32((uint8_t*)&client_rec, sizeof(microtcp_header_t));

	if (s != sizeof(microtcp_header_t) || client_rec.control != 2 || cs != rcs) {
		socket->state = INVALID;
		return -1;
	}
	
	socket->state = LISTEN;

	microtcp_header_t header = { 0 };
	header.seq_number = 0;
	header.ack_number = client_rec.seq_number + 1;
	header.control = 10;
	header.checksum = crc32((uint8_t*)&header, sizeof(microtcp_header_t));

	s = sendto(socket->sd, &header, sizeof(header), 0, address, address_len);
	if (s != sizeof(microtcp_header_t)) {
		socket->state = INVALID;
		return -1;
	}

	microtcp_header_t client_rec2;

	s = recvfrom(socket->sd, &client_rec2, sizeof(client_rec2), 0, address, &address_len);
	rcs = client_rec2.checksum;
	client_rec2.checksum = 0;
	cs = crc32((uint8_t*)&client_rec2, sizeof(microtcp_header_t));

	if (s != sizeof(microtcp_header_t) || client_rec2.control != 8 || cs != rcs) {
		socket->state = INVALID;
		return -1;
	}

	socket->state = ESTABLISHED;

	return 0;
}

int
microtcp_shutdown (microtcp_sock_t *socket, int how)
{
	
}

ssize_t
microtcp_send (microtcp_sock_t *socket, const void *buffer, size_t length,
							 int flags)
{
	/* Your code here */
}

ssize_t
microtcp_recv (microtcp_sock_t *socket, void *buffer, size_t length, int flags)
{
	/* Your code here */
}
