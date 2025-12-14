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


// TODO: set ack_number and seq_number to socket struct.

#include "microtcp.h"
#include "../utils/crc32.h"
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <time.h>

static int set_seed = 0;

#define FIN 1
#define SYN 2
#define RST 4
#define ACK 8

#define create_checksum(header) (header)->checksum = crc32((uint8_t*)(header), sizeof(microtcp_header_t))


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


/* converts all headers from host to network byte order */
static void header_to_net(microtcp_header_t *header) {
	header->seq_number	= htonl(header->seq_number);
	header->ack_number	= htonl(header->ack_number);
	header->control		= htons(header->control);
	header->window		= htons(header->window);
	header->data_len	= htonl(header->data_len);
	header->future_use0	= htonl(header->future_use0);
	header->future_use1	= htonl(header->future_use1);
	header->future_use2	= htonl(header->future_use2);
	header->checksum	= htonl(header->checksum);
}


/* converts all headers from network to host byte order */
static void header_to_host(microtcp_header_t *header) {
	header->seq_number	= ntohl(header->seq_number);
	header->ack_number	= ntohl(header->ack_number);
	header->control		= ntohs(header->control);
	header->window		= ntohs(header->window);
	header->data_len	= ntohl(header->data_len);
	header->future_use0	= ntohl(header->future_use0);
	header->future_use1	= ntohl(header->future_use1);
	header->future_use2	= ntohl(header->future_use2);
	header->checksum	= ntohl(header->checksum);
}


static int __check_checksum_header(microtcp_header_t header) {
	
	uint32_t rec_cs = header.checksum;
	header.checksum = 0;

	uint32_t cs = crc32((uint8_t*)&header, sizeof(microtcp_header_t));

	if (cs != rec_cs)
		return 0;

	return 1;
}


// static void print_header(microtcp_header_t hea)


#define check_checksum_header(header) \
	if (!__check_checksum_header(header)) { \
		return -1; \
	}

#define DEBUG 1


static void print_header(microtcp_header_t *header) {
	printf("[HEADER] Seq: %d\n", header->seq_number);
	printf("[HEADER] Ack: %d\n", header->ack_number);
	printf("[HEADER] Control: %d\n", header->control);
}

static int send_header(microtcp_sock_t *socket, microtcp_header_t *header, struct sockaddr *address, socklen_t address_len) {

	ssize_t s;

	header->seq_number = socket->seq_number;
	header->ack_number = socket->ack_number;

	header->checksum = 0;
	create_checksum(header);

#if DEBUG
	printf("Sent header: \n");
	print_header(header);
#endif

	header_to_net(header);
	s = sendto(socket->sd, header, sizeof(microtcp_header_t), 0, address, address_len);

	if (s != sizeof(microtcp_header_t)) {
		socket->state = INVALID;
		return -1;
	}
	return 0;
}


static int receive_header(microtcp_sock_t *socket, microtcp_header_t *header, struct sockaddr *address, socklen_t address_len) {
	ssize_t s;

	s = recvfrom(socket->sd, header, sizeof(microtcp_header_t), 0, address, &address_len);
	header_to_host(header);

#if DEBUG
	printf("Received header: \n");
	print_header(header);
#endif

	if (s != sizeof(microtcp_header_t))	{
		socket->state = INVALID;
		return -1;
	}

	socket->seq_number = header->ack_number;
	socket->ack_number = header->seq_number + 1;

	return 0;
}


static int rand32() {
	if (!set_seed) {
		srand(time(NULL) ^ getpid());
	}

#if !DEBUG
	return (rand() << 30) | (rand() << 15) | rand();
#else
	return rand() % 32;
#endif
}

int
microtcp_connect (microtcp_sock_t *socket, const struct sockaddr *address,
									socklen_t address_len)
{
	microtcp_header_t header = { 0 };
	socket->seq_number = rand32();
	socket->ack_number = 0;
	header.control = SYN;
	
	if (send_header(socket, &header, address, address_len))
		return -1;

	socket->state = LISTEN;

	microtcp_header_t ret;

	if (receive_header(socket, &ret, address, address_len))
		return -1;


	check_checksum_header(ret);

	if (ret.control != (ACK | SYN)) {
		socket->state = INVALID;
		printf("INVALID HEADER\n");
		return -1;
	}

	microtcp_header_t header2 = { 0 };
	header2.control = ACK;

	if (send_header(socket, &header2, address, address_len))
		return -1;

	socket->address = address;
	socket->address_len = address_len;

	socket->state = ESTABLISHED;

	return 0;
}


int
microtcp_accept (microtcp_sock_t *socket, struct sockaddr *address,
								 socklen_t address_len)
{

	microtcp_header_t client_rec;
	receive_header(socket, &client_rec, address, address_len);
	check_checksum_header(client_rec);

	if (client_rec.control != SYN) {
		socket->state = INVALID;
		return -1;
	}

	socket->state = LISTEN;

	microtcp_header_t header = { 0 };
	socket->seq_number = rand32();
	header.control = ACK | SYN;

	if (send_header(socket, &header, address, address_len))
		return -1;

	microtcp_header_t client_rec2;
	receive_header(socket, &client_rec2, address, address_len);
	check_checksum_header(client_rec2);

	if (client_rec2.control != ACK) {
		socket->state = INVALID;
		return -1;
	}

	socket->address = address;
	socket->address_len = address_len;

	socket->state = ESTABLISHED;

	return 0;
}

int shutdown_server(microtcp_sock_t *socket, int how) {

	microtcp_header_t ack_header = { 0 };
	ack_header.control = ACK;

	if (send_header(socket, &ack_header, socket->address, socket->address_len))
		return -1;

	socket->seq_number++;

	microtcp_header_t fin_header = { 0 };
	fin_header.control = FIN | ACK;

	if (send_header(socket, &fin_header, socket->address, socket->address_len))
		return -1;

	microtcp_header_t closing_header = { 0 };
	if (receive_header(socket, &closing_header, socket->address, socket->address_len))
		return -1;
	
	check_checksum_header(closing_header);

	if (closing_header.control != ACK) {
		return -1;
	}

	socket->state = CLOSED;
}

int shutdown_client(microtcp_sock_t *socket, int how) {

	microtcp_header_t fin_header = { 0 };
	fin_header.control = ACK | FIN;

	if (send_header(socket, &fin_header, socket->address, socket->address_len))
		return -1;

	microtcp_header_t h;

	microtcp_header_t ack_header = { 0 };

	if (receive_header(socket, &h, socket->address, socket->address_len))
		return -1;

	check_checksum_header(h);
	if (h.control == ACK) {
		socket->state = CLOSING_BY_HOST;
		ack_header = h;
	}
	else {
		fin_header = h;

	}

	if (receive_header(socket, &h, socket->address, socket->address_len))
		return -1;

	check_checksum_header(h);
	if (h.control == ACK) {
		socket->state = CLOSING_BY_HOST;
		ack_header = h;
	}
	else {
		fin_header = h;

	}

	// TODO: check if both headers arrived
	socket->seq_number = ack_header.ack_number;
	socket->ack_number = fin_header.seq_number + 1;

	microtcp_header_t closing_header = { 0 };
	closing_header.control = ACK;

	if (send_header(socket, &closing_header, socket->address, socket->address_len))
		return -1;

	socket->state = CLOSED;
}



int
microtcp_shutdown (microtcp_sock_t *socket, int how)
{
	if (socket->state == CLOSING_BY_PEER) {
		return shutdown_server(socket, how);
	}
	else {
		return shutdown_client(socket, how);
	}
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
