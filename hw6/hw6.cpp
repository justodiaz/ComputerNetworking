#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>

#include <iostream>
#include <cstddef> //size_t
#include <cstdint> //uint#_t
#include "hw6.h"

uint32_t sequence_number;
uint32_t ack_number;

int timeval_to_msec(struct timeval *t) { 
	return t->tv_sec*1000+t->tv_usec/1000;
}

void msec_to_timeval(int millis, struct timeval *out_timeval) {
	out_timeval->tv_sec = millis/1000;
	out_timeval->tv_usec = (millis%1000)*1000;
}

int current_msec() {
	struct timeval t;
	gettimeofday(&t,0);
	return timeval_to_msec(&t);
}

int rel_connect(int socket,struct sockaddr_in *toaddr,int addrsize) {
		 connect(socket,(struct sockaddr*)toaddr,addrsize);
}

int rel_rtt(int socket) {
		 return 1000;
}

void make_pkt(uint32_t seq_num, uint32_t ack_num, void *data, size_t data_len, 
			  void *pkt, size_t pkt_sz){
	
	if(pkt_sz < HDR_SZ || pkt_sz < data_len) return;

	hdr_ptr pkt_hdr = (hdr_ptr)pkt;
	memset(pkt,0,pkt_sz);	
	pkt_hdr->sequence_number = htonl(seq_num);
	pkt_hdr->ack_number = htonl(ack_num);

	memcpy(pkt_hdr+1,data,data_len);
}

bool isACK(void *rcvpkt, uint32_t ack_num){
	hdr_ptr hdr = (hdr_ptr)rcvpkt;
	
	return ntohl(hdr->ack_number) == ack_num;
}

bool has_seq(void *rcvpkt, uint32_t seq_num){
	hdr_ptr hdr = (hdr_ptr)rcvpkt;
	
	std::cerr << "Got packet " << ntohl(hdr->sequence_number) << std::endl;

	return ntohl(hdr->sequence_number) == seq_num;	
}

//caller gurantees len will be no longer than MAX_SEGMENT
void rel_send(int sock, void *buf, int len)
{
	uint8_t sndpkt[MAX_PACKET];
	uint8_t rcvpkt[MAX_PACKET];

	make_pkt(sequence_number,ack_number,buf,(size_t)len,sndpkt,MAX_PACKET);

	do{
		send(sock, sndpkt, HDR_SZ+len, 0);
		memset(rcvpkt, 0, MAX_PACKET);
		//start timer
		//unsigned start = current_msec();
		//alarm(TimeoutInterval);
		//should timeout if doesn't recieve ack
		//should block until ack is received
		recv(sock, rcvpkt, MAX_PACKET, 0);
		//if(ret<0){ if(errno == EINTR) timeout = true; else exit(1); }
		//unsigned end = current_msec();
		//unsigned SampleRTT = end - start;
		//DevRTT = (1-.25) * DevRTT + .25 * abs(SampleRTT - EstimatedRTT);
		//EstimatedRTT = (1-.125) * EstimatedRTT + .125 * SampleRTT;
		//TimeoutInterval = EstimatedRTT + 4 * DevRTT;
		
	} while( /*sock timeout or */ !isACK(rcvpkt,sequence_number)); //resend
	

	sequence_number++;
}

int rel_socket(int domain, int type, int protocol) {
	sequence_number = 0;
	ack_number = 0;
	return socket(domain, type, protocol);
}


int rel_recv(int sock, void * buffer, size_t length) {
	uint8_t rcvpkt[MAX_PACKET];
	memset(&rcvpkt,0,MAX_PACKET);
	uint8_t sndpkt[HDR_SZ];
//	hdr_ptr hdr=(hdr_ptr)rcvpkt;	

	struct sockaddr_in fromaddr;
	unsigned addrlen=sizeof(fromaddr);	
	int recv_count = recvfrom(sock, rcvpkt, MAX_PACKET, 0, (struct sockaddr*)&fromaddr, &addrlen);		

	// this is a shortcut to 'connect' a listening server socket to the incoming client.
	// after this, we can use send() instead of sendto(), which makes for easier bookkeeping
	if(connect(sock, (struct sockaddr*)&fromaddr, addrlen)) {
		std::cerr << "couldn't connect socket" << std::endl;
	}


	while(!has_seq(rcvpkt,ack_number)){
		make_pkt(sequence_number,ack_number-1,NULL,0,sndpkt,HDR_SZ);
		send(sock,sndpkt,HDR_SZ,0);
 
		memset(&rcvpkt,0,MAX_PACKET);
		recv_count = recv(sock,rcvpkt,MAX_PACKET,0);
	}	

	make_pkt(sequence_number,ack_number,NULL,0,sndpkt,HDR_SZ);
	send(sock,sndpkt,HDR_SZ,0);

	ack_number++;

	memcpy(buffer, rcvpkt+HDR_SZ, recv_count-HDR_SZ);

	return recv_count-HDR_SZ;
}

int rel_close(int sock) {
	rel_send(sock, 0, 0); // send an empty packet to signify end of file
	close(sock);
}

