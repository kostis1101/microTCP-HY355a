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


/* +----------+
 * |Suggestion|
 * +----------+
 * We can have two buffers that are statically allocated:
 * - One for receiving packets
 * - One for sending packets
 * Since we know the maximum size of a packet, we can use those to receive and send data
 * This way, we can split the receiving/sending part of the transmittion into separate function
 * that set the header values, calculate the checksum and convert from/to network byte order.
 * The receiving function will first read the header and then read the amount of bytes that are
 * specified in the header.
 * This can also be helpfull when receiving ACKs after sending packets: When waiting for an ACK
 * we can to receive a whole packet (i.e. not just the header that we are receiving now) and check
 * if that is an ACK (e.g. it might be a data packet that arrived late).
 */

//testing 

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

	socket->seq_number++;

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

	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = MICROTCP_ACK_TIMEOUT_US;

	if (setsockopt(socket->sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)) < 0) {
		perror("setsockopt failed");
	}

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

	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = MICROTCP_ACK_TIMEOUT_US;

	if (setsockopt(socket->sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)) < 0) {
		perror("setsockopt failed");
	}

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
	// only allocate at start of the programme. No need to allocate every time.
	// TODO: move packet as global variable to be allocated at begin of the connection.
	static uint8_t *packet = NULL;
	if (!packet)
		packet = malloc(MICROTCP_MSS + sizeof(microtcp_header_t));

	// (maybe?): for speed, cache checksums to skip recomputation on lost packets (probably to much, only if we have too much time)

	size_t remaining = length;
	size_t data_sent = 0;
	size_t flow_ctrl_win = socket->curr_win_size;

	uint32_t first_seq_number = socket->seq_number;

	printf("Client: sending data (start)\n");

	microtcp_header_t header = { 0 };
	while (data_sent < length) {
start_send:
		size_t bytes_to_send = min3(flow_ctrl_win, socket->cwnd, remaining);
		size_t chunks = bytes_to_send / MICROTCP_MSS + (int)(bytes_to_send % MICROTCP_MSS != 0);

		size_t buffer_index = 0;

		header.ack_number = socket->ack_number;
		header.seq_number = socket->seq_number;
		while (buffer_index < bytes_to_send) {
			header.checksum = 0;

			header.data_len = (bytes_to_send - buffer_index > MICROTCP_MSS) ? MICROTCP_MSS : (bytes_to_send - buffer_index);

			printf("Sending packet with seq number %u\n", header.seq_number);

			printf("[DEBUG] buffer_index %u\n", buffer_index);
			
			memcpy(packet, &header, sizeof(microtcp_header_t));
			memcpy(packet + sizeof(microtcp_header_t), buffer + buffer_index, header.data_len);

			uint32_t full_checksum = crc32((uint8_t*)packet, sizeof(microtcp_header_t) + header.data_len);
			((microtcp_header_t*)packet)->checksum = full_checksum;

			/* We only need to convert the header to network byte order.
			   We cannot make any further assumption about the transmitted data */
			header_to_net((microtcp_header_t*)packet);

			sendto(socket->sd, packet, sizeof(microtcp_header_t) + header.data_len, 0, socket->address, socket->address_len);

			printf("data length after send: %u\n", header.data_len);
			header.seq_number += header.data_len;
			buffer_index += header.data_len;
		}

		/* Get the ACKs */
		microtcp_header_t ack_header;
		uint32_t last_ack = socket->seq_number;
		int dupcount = 1;
		// (maybe?): possibly, instead of a for loop, check a while loop until an ACK of the last sequence number is given.
		for (int i = 0; i < chunks; i++) {
			ssize_t ret = recvfrom(socket->sd, &ack_header, sizeof(microtcp_header_t), 0, socket->address, socket->address_len);
			if (ret < 0) {
				printf("[DEBUG] Packet timeout, retransmit...\n");
				goto retransmit;
			}

			header_to_host(&ack_header);
			printf("Received ack  %u\n", ack_header.ack_number);
			if (!__check_checksum_header(ack_header)) {
				goto retransmit;
			}

			// 3dup retrasmisions
			if (last_ack == ack_header.ack_number) {
				dupcount++;
			} else {
				dupcount = 1;
				last_ack = ack_header.ack_number;
			}
			/* 3 duplicate retransmission */
			if (dupcount == 3){
				printf("3 duplicate acks for %u, retransmitting\n", last_ack);
retransmit:
				buffer += last_ack - first_seq_number; // move buffer to the first byte that was not trassmitted
				socket->seq_number = last_ack;
				data_sent = last_ack - first_seq_number; // update number of data sent
				remaining = length - data_sent;
				goto start_send; // start all over from the first lost byte
			}
		}
		socket->seq_number = last_ack;

		/* Retransmissions */

		/* Update window */

		/* Update congestion control */

		remaining -= bytes_to_send;
		data_sent += bytes_to_send;
		buffer += bytes_to_send; // move buffer pointer to first untrassmitted byte
	}

	return data_sent;
}

void send_ack(microtcp_sock_t *socket) {
	microtcp_header_t ack_header = { 0 };
	ack_header.control = ACK;
	ack_header.window = socket->my_curr_win_size;	
	ack_header.ack_number = socket->ack_number;
	// send ack
	send_header(socket, &ack_header, socket->address, socket->address_len);
}
ssize_t
microtcp_recv (microtcp_sock_t *socket, void *buffer, size_t length, int flags)
{
	// TODO; this needs to be done before here, ack got a value one time higher than should
	
	/* receive packet */
	int total_size = 0;
	size_t received = 0;
	uint8_t *packet = malloc(MICROTCP_MSS + sizeof(microtcp_header_t));
	microtcp_header_t *header;
	while (received < length) {

		recvfrom(socket->sd, packet, MICROTCP_MSS + sizeof(microtcp_header_t), 0, socket->address, socket->address_len);
		header = (microtcp_header_t*)packet;

		header_to_host(header);
		total_size =  header->data_len + sizeof(microtcp_header_t);
		// TODO: network to host bytes
		// TODO: window size implementation

		// Compute checksum and verify
		u_int32_t rec_checksum = header->checksum;
		header->checksum = 0;
		u_int32_t calculated_checksum = crc32((uint8_t*)packet, total_size);
		if (rec_checksum!= calculated_checksum){
			printf("Error in checksum! Dropping packet with seq number %u\n",header->seq_number);
			// send back ACK for last correct packet
			socket->seq_number += sizeof(microtcp_header_t);
			send_ack(socket);
			continue;
		}
		if (socket->ack_number != header->seq_number ){
			printf("Out of order packet! Dropping packet with seq number %u, expected %u\n",header->seq_number, socket->ack_number);
			send_ack(socket);
			exit(-1);
			continue;
		}
		// update ack and seq numbers
		socket->ack_number += header->data_len;
		printf("Sended ack for packet with seq number: %u and ack number %u\n", header->seq_number, socket->ack_number);
		// send back ACK
		send_ack(socket);
		// copy data to buffer
		memcpy(buffer,packet,total_size);

		// TODO: we should not deliver headers, only data!!!! must change
		buffer += total_size;
		received += total_size;
	}

	/* check FIN bit -> shutdown server */
}