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
#include <unistd.h>
#include <string.h>

static int set_seed = 0;

// tcp flags
#define FIN 1
#define SYN 2
#define RST 4
#define ACK 8

#define DEBUG 0
#define THANOS_DEBUG 0


#define create_checksum(header) (header)->checksum = crc32((uint8_t*)(header), sizeof(microtcp_header_t))


microtcp_sock_t
microtcp_socket (int domain, int type, int protocol)
{
	int sock;

	// open udp socket
	if ((sock = socket(domain, type, protocol)) == -1) {
		perror( " SOCKET COULD NOT BE OPENED " );
		exit( EXIT_FAILURE );
	}

	microtcp_sock_t socket = { 0 };

	socket.sd = sock;
	socket.state = INVALID;

	socket.my_init_win_size = MICROTCP_WIN_SIZE;
	socket.my_curr_win_size = MICROTCP_WIN_SIZE;
	socket.recvbuf = malloc(MICROTCP_WIN_SIZE);
	socket.cwnd = MICROTCP_INIT_CWND;
	socket.ssthresh = MICROTCP_INIT_SSTHRESH;

	return socket;
}

int
microtcp_bind (microtcp_sock_t *socket, const struct sockaddr *address,
							 socklen_t address_len)
{
	int res;
	// bind the port
	if ((res = bind(socket->sd, address, address_len)) == -1) {
		perror("TCP error");
		exit(EXIT_FAILURE);
	}
	return res;
}


/* converts all header fields from host to network byte order */
void header_to_net(microtcp_header_t *header) {
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


/* converts all header fields from network to host byte order */
void header_to_host(microtcp_header_t *header) {
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

	// calculate checksum of received header
	uint32_t cs = crc32((uint8_t*)&header, sizeof(microtcp_header_t));

	// verify data integrity
	if (cs != rec_cs)
		return 0;

	return 1;
}


#define check_checksum_header(header) \
	if (!__check_checksum_header(header)) { \
		return -1; \
	}


/* prints the relevant fields for a header */
void print_header(microtcp_header_t *header) {
	printf("[HEADER] Seq: %d\n", header->seq_number);
	printf("[HEADER] Ack: %d\n", header->ack_number);
	printf("[HEADER] Control: %d\n", header->control);
}

/* sends a header to the address */
static int send_header(microtcp_sock_t *socket, microtcp_header_t *header, struct sockaddr *address, socklen_t address_len) {

	ssize_t s;

#if DEBUG
	sleep(2);
#endif

	// set seq numbers before sending
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


/* receives a packet containing only one header */
static int receive_header(microtcp_sock_t *socket, microtcp_header_t *header, struct sockaddr *address, socklen_t address_len) {
	ssize_t s;


	s = recvfrom(socket->sd, header, sizeof(microtcp_header_t), 0, address, &address_len);
	header_to_host(header);

#if DEBUG

# if THANOS_DEBUG
	sleep(1);
# endif

	printf("Received header: \n");
	print_header(header);
#endif

	if (s != sizeof(microtcp_header_t))	{
		socket->state = INVALID;
		return -1;
	}

	// update numbers for next packet
	socket->seq_number = header->ack_number;
	socket->ack_number = header->seq_number + 1;

	return 0;
}

/* generates a 32 bit random number */
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

// client side connect
int
microtcp_connect (microtcp_sock_t *socket, const struct sockaddr *address,
									socklen_t address_len)
{
	microtcp_header_t header = { 0 };
	socket->seq_number = rand32();
	socket->ack_number = 0;
	header.control = SYN;
	header.window = socket->my_init_win_size;


	socket->address = address;
	socket->address_len = address_len;
	
	// step 1: send SYN
	if (send_header(socket, &header, address, address_len))
		return -1;

	socket->state = LISTEN;

	microtcp_header_t ret;

	// step 2: wait for SYN-ACK
	if (receive_header(socket, &ret, address, address_len))
		return -1;

	check_checksum_header(ret);

	if (ret.control != (ACK | SYN)) {
		socket->state = INVALID;
		printf("INVALID HEADER\n");
		return -1;
	}

	socket->init_win_size = ret.window;
	socket->curr_win_size = ret.window;

	microtcp_header_t header2 = { 0 };
	header2.control = ACK;

	// step 3: send ACK
	if (send_header(socket, &header2, address, address_len))
		return -1;

	socket->address = address;
	socket->address_len = address_len;

	socket->state = ESTABLISHED;

	return 0;
}


// server side accept
int
microtcp_accept (microtcp_sock_t *socket, struct sockaddr *address,
								 socklen_t address_len)
{

	microtcp_header_t client_rec;
	// wait for syn
	receive_header(socket, &client_rec, address, address_len);
	check_checksum_header(client_rec);

	socket->address = address;
	socket->address_len = address_len;

	if (client_rec.control != SYN) {
		socket->state = INVALID;
		return -1;
	}

	socket->state = LISTEN;
	socket->init_win_size = client_rec.window;
	socket->curr_win_size = client_rec.window;

	microtcp_header_t header = { 0 };
	header.window = socket->my_init_win_size;
	socket->seq_number = rand32();
	header.control = ACK | SYN;

	// send syn ack
	if (send_header(socket, &header, address, address_len))
		return -1;

	microtcp_header_t client_rec2;
	// wait for final ack
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

// close logic for server
int shutdown_server(microtcp_sock_t *socket, int how) {

	microtcp_header_t ack_header = { 0 };
	ack_header.control = ACK;

	// send ack
	if (send_header(socket, &ack_header, socket->address, socket->address_len))
		return -1;

	socket->seq_number++;

	microtcp_header_t fin_header = { 0 };
	fin_header.control = FIN | ACK;

	// send fin
	if (send_header(socket, &fin_header, socket->address, socket->address_len))
		return -1;

	microtcp_header_t closing_header = { 0 };
	// wait for ack
	if (receive_header(socket, &closing_header, socket->address, socket->address_len))
		return -1;
	
	check_checksum_header(closing_header);

	if (closing_header.control != ACK) {
		return -1;
	}

	socket->state = CLOSED;
}

// close logic for client
int shutdown_client(microtcp_sock_t *socket, int how) {

	microtcp_header_t fin_header = { 0 };
	fin_header.control = ACK | FIN;

	// send fin-ack
	if (send_header(socket, &fin_header, socket->address, socket->address_len))
		return -1;

	microtcp_header_t h;

	microtcp_header_t ack_header = { 0 };

	// wait for ack or fin-ack
	if (receive_header(socket, &h, socket->address, socket->address_len))
		return -1;

	check_checksum_header(h);

	// check if it is ack or fin-ack
	if (h.control == ACK) {
		socket->state = CLOSING_BY_HOST;
		ack_header = h;
	}
	else {
		fin_header = h;

	}

	// wait for ack or fin-ack
	if (receive_header(socket, &h, socket->address, socket->address_len))
		return -1;

	check_checksum_header(h);

	// check if it is ack or fin-ack
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

	// send final ack: connection closed
	if (send_header(socket, &closing_header, socket->address, socket->address_len))
		return -1;

	socket->state = CLOSED;
}



int
microtcp_shutdown (microtcp_sock_t *socket, int how)
{
	// check who is closing
	if (socket->state == CLOSING_BY_PEER) {
		return shutdown_server(socket, how);
	}
	else {
		return shutdown_client(socket, how);
	}
}


/* sends some packets. To be called from the microtcp_send. Should get the start packet index when retrasmitting */
/*ssize_t send_packets(...);


int check_order(...);*/


int min3(int a, int b, int c) {
	if (a > b)
		a = b;
	if (a > c)
		a = c;
	return a;
}


ssize_t
microtcp_send (microtcp_sock_t *socket, const void *buffer, size_t length, int flags)
{
	size_t remaining = length;
	size_t data_sent = 0;
	size_t flow_ctrl_win = socket->curr_win_size;

	printf("Client: sending data (start)\n");

	uint8_t *packet = malloc(MICROTCP_MSS + sizeof(microtcp_header_t));
	microtcp_header_t header = { 0 };

	while (data_sent < length) {
		size_t bytes_to_send = min3(flow_ctrl_win, socket->cwnd, remaining);
		size_t chunks = bytes_to_send / MICROTCP_MSS;

		for (int i = 0; i < chunks; i++){
			header.seq_number = socket->seq_number;
			header.ack_number = socket->ack_number;
			header.data_len = MICROTCP_MSS;

			printf("Sending packet with seq number %u\n", header.seq_number);
			
			memcpy(packet, &header, sizeof(microtcp_header_t));
			memcpy(packet + sizeof(microtcp_header_t), buffer + (i * MICROTCP_MSS), MICROTCP_MSS);
			sendto(socket->sd, packet, sizeof(microtcp_header_t) + header.data_len, 0, socket->address, socket->address_len);

			printf("data length after send: %u", header.data_len);
			socket->seq_number += header.data_len;
		}
		/* Check if there is a semi - filled chunk
		*/
		if (bytes_to_send % MICROTCP_MSS) {
			header.seq_number = socket->seq_number;
			header.ack_number = socket->ack_number;
			header.data_len = bytes_to_send - chunks * MICROTCP_MSS;
			
			memcpy(packet, &header, sizeof(microtcp_header_t));
			memcpy(packet + sizeof(microtcp_header_t), buffer + (chunks * MICROTCP_MSS), header.data_len);
			sendto(socket->sd, packet, sizeof(microtcp_header_t) + header.data_len, 0, socket->address, socket->address_len);

			chunks++;
			socket->seq_number += header.data_len;
		}

		/* Get the ACKs */
		for (int i = 0; i < chunks; i++) {
			// recvfrom();
			/* check correct ACK numbers that arrived */
			/* 3 duplicate retransmission */
		}
		/* Retransmissions */

		/* Update window */

		/* Update congestion control */

		remaining -= bytes_to_send;
		data_sent += bytes_to_send;
	}

	return data_sent;
}

ssize_t
microtcp_recv (microtcp_sock_t *socket, void *buffer, size_t length, int flags)
{
	/* receive packet */

	size_t received = 0;

	while (received < length) {
		recvfrom(socket->sd, buffer, MICROTCP_MSS + sizeof(microtcp_header_t), 0, socket->address, socket->address_len);
		printf("seq_number received: %d\n", ((microtcp_header_t*)buffer)->seq_number);
		buffer += MICROTCP_MSS + sizeof(microtcp_header_t);
		received += MICROTCP_MSS + sizeof(microtcp_header_t);
	}

	/* check FIN bit -> shutdown server */

	/* error checking and order checking */

	/* put into buffer */

	/* update window size, ... */

	/* send ACK and remaining window size */
}