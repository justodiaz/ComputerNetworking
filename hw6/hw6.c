#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include "hw6.h"

int sequence_number;

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

void rel_send(int sock, void *buf, int len)
{
 	// make the packet = header + buf
	char packet[1400];
	struct hw6_hdr *hdr = (struct hw6_hdr*)packet;
	hdr->sequence_number = htonl(sequence_number);
	memcpy(hdr+1,buf,len); //hdr+1 is where the payload starts
	
	send(sock, packet, sizeof(struct hw6_hdr)+len, 0);
	sequence_number++;
}

int rel_socket(int domain, int type, int protocol) {
	sequence_number = 0;
	return socket(domain, type, protocol);
}

int rel_recv(int sock, void * buffer, size_t length) {
	char packet[MAX_PACKET];
	memset(&packet,0,sizeof(packet));
	struct hw6_hdr* hdr=(struct hw6_hdr*)packet;	

	struct sockaddr_in fromaddr;
	unsigned int addrlen=sizeof(fromaddr);	
	int recv_count = recvfrom(sock, packet, MAX_PACKET, 0, (struct sockaddr*)&fromaddr, &addrlen);		

	// this is a shortcut to 'connect' a listening server socket to the incoming client.
	// after this, we can use send() instead of sendto(), which makes for easier bookkeeping
	if(connect(sock, (struct sockaddr*)&fromaddr, addrlen)) {
		perror("couldn't connect socket");
	}

	fprintf(stderr, "Got packet %d\n", ntohl(hdr->sequence_number));

	memcpy(buffer, packet+sizeof(struct hw6_hdr), recv_count-sizeof(struct hw6_hdr));
	return recv_count - sizeof(struct hw6_hdr);
}

int rel_close(int sock) {
	rel_send(sock, 0, 0); // send an empty packet to signify end of file
	close(sock);
}

