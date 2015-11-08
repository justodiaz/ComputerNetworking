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
#include <cerrno>
#include "hw6.h"

#define debug

uint32_t sequence_number;
uint32_t ack_number;
uint32_t devRTT;
uint32_t estimatedRTT;
uint32_t first_acks;

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
#ifdef debug	
	std::cerr << "Got packet " << ntohl(hdr->sequence_number);
	std::cerr << ", Expected " << seq_num << std::endl;
#endif

	return ntohl(hdr->sequence_number) == seq_num;	
}

void set_timeout_sock(int sock, uint32_t start, uint32_t end){
	uint32_t timeoutInterval;

	//TCP, only use estimatedRTT and devRTT after two acks
	//First ack RTT is set as estimatedRTT	
	if(first_acks < 2) {
		timeoutInterval = INIT_TO;
	}

	else timeoutInterval = estimatedRTT + 4*devRTT;

	uint32_t diff = end - start;//to subtract from timeout clock the time passed

	if(timeoutInterval > diff) timeoutInterval -= diff;
	else timeoutInterval = 1; //Really means timeout should happen soon.

#ifdef debug
	std::cerr <<"timeoutInterval: " << timeoutInterval <<std::endl;
#endif
	struct timeval to;
	msec_to_timeval(timeoutInterval,&to); 
	setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,&to,sizeof(to));
}

//To implement timeouts, we set recv timeout options on sock with UDP protocol
//For safety, we will save and restore any previous timeout opt. set when using the socket
void save_sockopt(int sock, struct timeval *save){
	socklen_t len = sizeof(struct timeval);

	int ret = getsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,save,&len);
	if(ret<0 || len != sizeof(struct timeval)){
		perror("getsockopt");
		exit(1);
	}
}

void restore_sockopt(int sock, struct timeval *save){
	int ret = setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,save,sizeof(struct timeval));
	if(ret<0){
		perror("setsockopt");
		exit(1);
	}
}
//caller gurantees len will be no longer than MAX_SEGMENT
void rel_send(int sock, void *buf, int len)
{
	uint8_t sndpkt[MAX_PACKET];
	uint8_t rcvpkt[MAX_PACKET];
	bool timeout = false, get_sampleRTT = true; //TCP deson't compute for retransmitted segments
	uint32_t start, end, sampleRTT;

	struct timeval save;
	save_sockopt(sock,&save);

	make_pkt(sequence_number,ack_number,buf,(size_t)len,sndpkt,MAX_PACKET);

	do{
		memset(rcvpkt, 0, MAX_PACKET);
		timeout = false;
		send(sock, sndpkt, HDR_SZ+len, 0);

		start = current_msec();
		end = start;

		while(1){
			set_timeout_sock(sock,start,end);
			int ret = recv(sock, rcvpkt, MAX_PACKET, 0);
			end = current_msec();
			if(ret<0){
				if(errno == EAGAIN || errno == EWOULDBLOCK ) {
					std::cerr << "timeout" << std::endl;
					timeout = true; 
					get_sampleRTT = false;
					break;
				}
				else { 
					perror("recv"); 
					exit(1);
				} 
			}
			else if(isACK(rcvpkt,sequence_number)){
				if(get_sampleRTT){
					sampleRTT = end - start;	
					
					if(first_acks == 0){
						first_acks++;
						estimatedRTT = sampleRTT;
					}
					else if(first_acks == 1){
						first_acks++;//timeInterval can now be changed
					}

					estimatedRTT = (1-.125)*estimatedRTT + .125*sampleRTT;
					devRTT = (1-.25)*devRTT + .25*diff(sampleRTT,estimatedRTT);
					#ifdef debug
					std::cerr << "estimatedRTT: " << estimatedRTT << std::endl;
					#endif
				}

				break;
			}
		}

	} while(timeout); //resend
	
	restore_sockopt(sock,&save);	

	sequence_number++;
}

int rel_socket(int domain, int type, int protocol) {
	sequence_number = 0;
	ack_number = 0;
	devRTT = 0;
	estimatedRTT = 0;
	first_acks = 0;
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

