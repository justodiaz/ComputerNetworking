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

void make_pkt(int seq_num, char *data, int data_len, char *packet){
	hdr_ptr pkt_hdr = (hdr_ptr)packet;
	memset(packet,0,MAX_PACKET);	
	pkt_hdr->sequence_number = htonl(seq_num);
	pkt_hdr->ack_number = htonl(0);

	memcpy(pkt_hdr+1,data,data_len);
}

int isACK(char *rcvpkt, int ack_num){
	hdr_ptr hdr = (hdr_ptr)rcvpkt;
	
	return ntohl(hdr->ack_number) == ack_num;
}

//caller gurantees len will be no longer than MAX_SEGMENT
void rel_send(int sock, void *buf, int len)
{
 	// make the packet = header + buf
	char packet[MAX_PACKET];
	//hdr_ptr hdr = (hdr_ptr)packet;

	//hdr->sequence_number = htonl(sequence_number); //Don't think htonl is necessary
	//hdr->ack_number = htonl(0);

	//memcpy(hdr+1,buf,len); //hdr+1 is where the payload starts
	make_pkt(sequence_number,buf,len,packet);

	char rcvpkt[MAX_PACKET];
	do{
		//udt_send(packet)
		send(sock, packet,HDR_SZ+len, 0);
		//await for ack
		memset(rcvpkt,0,MAX_PACKET);
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
	return socket(domain, type, protocol);
}

int has_seq(char *rcvpkt, int seq_num){
	hdr_ptr hdr = (hdr_ptr)rcvpkt;
	
	fprintf(stderr, "Got packet %d\n", ntohl(hdr->sequence_number));

	return ntohl(hdr->sequence_number) == seq_num;	
}

void make_ack(char *sndpkt, int ack_num){
	hdr_ptr hdr = (hdr_ptr)sndpkt;
	hdr->ack_number = htonl(ack_num);
	hdr->sequence_number = htonl(0);
}

int rel_recv(int sock, void * buffer, size_t length) {
	char packet[MAX_PACKET];
	memset(&packet,0,sizeof(packet));
//	hdr_ptr hdr=(hdr_ptr)packet;	

	struct sockaddr_in fromaddr;
	unsigned int addrlen=sizeof(fromaddr);	
	int recv_count = recvfrom(sock, packet, MAX_PACKET, 0, (struct sockaddr*)&fromaddr, &addrlen);		

	// this is a shortcut to 'connect' a listening server socket to the incoming client.
	// after this, we can use send() instead of sendto(), which makes for easier bookkeeping
	if(connect(sock, (struct sockaddr*)&fromaddr, addrlen)) {
		perror("couldn't connect socket");
	}

	char sndpkt[HDR_SZ];

	while(!has_seq(packet,sequence_number)){
		make_ack(sndpkt,sequence_number-1);
		send(sock,sndpkt,HDR_SZ,0);
 
		memset(&packet,0,sizeof(packet));
		recv_count = recv(sock,packet,MAX_PACKET,0);
	}	

	make_ack(sndpkt,sequence_number);
	send(sock,sndpkt,HDR_SZ,0);

	sequence_number++;

	memcpy(buffer, packet+HDR_SZ, recv_count-HDR_SZ);
	return recv_count-HDR_SZ;
}

int rel_close(int sock) {
	rel_send(sock, 0, 0); // send an empty packet to signify end of file
	close(sock);
}

