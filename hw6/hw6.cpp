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
#include <csignal> //sigaction
#include <cstddef> //size_t
#include <cstdint> //uint#_t
#include <cerrno>
#include "hw6.h"

#define TIMEWAIT 5000 //for fin ack to server, in milliseconds

#define debug

uint32_t sequence_number;
uint32_t ack_number;
uint32_t devRTT;
uint32_t estimatedRTT;
uint32_t first_acks;
bool server;
bool timeout; 

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


bool isSYNACK(void *rcvpkt, uint32_t expected_ack_num){
	hdr_ptr hdr = (hdr_ptr)rcvpkt;
	return (hdr->flags & ACK) && (hdr->flags & SYN) && hdr->ack_number == expected_ack_num;
}

int rel_connect(int socket,struct sockaddr_in *toaddr,int addrsize) {
//
//	sequence_number = 0;//TCP randomizes
//	uint8_t sndpkt[HDR_SZ];
//	uint8_t rcvpkt[HDR_SZ];
//		
//	make_pkt(sequence_number,0,SYN,NULL,0,sndpkt,HDR_SZ);
	
	connect(socket,(struct sockaddr*)toaddr,addrsize);

//	do{
//		send(socket,sndpkt,HDR_SZ,0);
//		recv(socket,rcvpkt,HDR_SZ,0);
//	} while(!isSYNACK(rcvpkt,sequence_number));
//
//	hdr_ptr hdr = (hdr_ptr)rcvpkt;
//	ack_number = ntohl(hdr->ack_number);

	

}

int rel_rtt(int socket) {
	return estimatedRTT;
}

void make_pkt(uint32_t seq_num, uint32_t ack_num, uint8_t flags, void *data, size_t len, 
			  void *pkt, size_t pkt_sz){
	
	if(pkt_sz < HDR_SZ || pkt_sz < len) {
		std::cerr << "make_pkt: error, not enough buffer space" << std::endl;
		exit(1);
	}

	hdr_ptr hdr = (hdr_ptr)pkt;
	memset(pkt,0,pkt_sz);	

	hdr->sequence_number = htonl(seq_num);
	hdr->ack_number = htonl(ack_num);
	hdr->flags = flags;

	memcpy(hdr+1,data,len);
}

bool isACK(void *rcvpkt, uint32_t expected_ack_num){
	hdr_ptr hdr = (hdr_ptr)rcvpkt;
	
	return (hdr->flags & ACK) && ntohl(hdr->ack_number) == expected_ack_num;
}

bool has_seq(void *rcvpkt, uint32_t seq_num){
	hdr_ptr hdr = (hdr_ptr)rcvpkt;
#ifdef debug	
	std::cerr << "Got packet " << ntohl(hdr->sequence_number);
	std::cerr << ", Expected " << seq_num << std::endl;
#endif

	return ntohl(hdr->sequence_number) == seq_num;	
}

bool has_seq_fin(void *rcvpkt, uint32_t seq_num){
	hdr_ptr hdr = (hdr_ptr)rcvpkt;

#ifdef debug	
	std::cerr << "Has FIN? " << (hdr->flags & FIN) ;
	std::cerr << ", Got packet " << ntohl(hdr->sequence_number);
	std::cerr << ", Expected " << seq_num << std::endl;
#endif

	return (hdr->flags & FIN) && ntohl(hdr->sequence_number) == seq_num;	
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

void compute_sample_RTT(uint32_t start, uint32_t end){
	uint32_t sampleRTT;

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

void handle_sigalarm(int sig){
	#ifdef debug
	std::cerr << "*** Timeout ***" << std::endl;
	#endif
	timeout = true;
}

void rel_send_flags(int sock, void *buf, int len, uint8_t flags){
	uint8_t sndpkt[MAX_PACKET];
	uint8_t rcvpkt[MAX_PACKET];
	bool retransmit = false;
	uint32_t start, end;

	make_pkt(sequence_number,ack_number,flags,buf,(size_t)len,sndpkt,MAX_PACKET);

	uint32_t timeoutInterval;

	//TCP, only use estimatedRTT and devRTT after two acks
	//First ack RTT is set as estimatedRTT	
	if(first_acks < 2) 
		timeoutInterval = INIT_TO;
	else 
		timeoutInterval = estimatedRTT + 4*devRTT;

#ifdef debug
	std::cerr <<"timeoutInterval: " << timeoutInterval <<std::endl;
#endif

	struct itimerval timer = {{0,0}, {0,0}};
	msec_to_timeval(timeoutInterval,&timer.it_value);
	timer.it_interval = timer.it_value;

	if(setitimer(ITIMER_REAL,&timer,NULL)){perror("setitimer");exit(1);}

	do{
		memset(rcvpkt, 0, MAX_PACKET);
		timeout = false;

		#ifdef debug
		std::cerr <<"Sending packet" << std::endl;
		#endif

		send(sock, sndpkt, HDR_SZ+len, 0);
		start = current_msec();

		while(1){
			int ret = recv(sock, rcvpkt, MAX_PACKET, 0);
			end = current_msec();

			#ifdef debug
			if(getitimer(ITIMER_REAL,&timer)){perror("getitimer");exit(1);}
			std::cerr <<"Time on clock: " << timeval_to_msec(&timer.it_value) <<std::endl;
			#endif
			
			if(ret<0){
				if(errno == EINTR && timeout) {
					retransmit = true;
					break;
				}
				else if(errno == ECONNREFUSED){
					#ifdef debug
					std::cerr << "Connection refused" << std::endl;
					#endif
					return;
				}
				else { 
					perror("recv"); 
					exit(1);
				} 
			}
			else if(isACK(rcvpkt,sequence_number)){
				#ifdef debug
				std::cerr << "Got ACK!" <<std::endl;
				#endif 
				//stop timer
				timer = {{0,0},{0,0}};
				if(setitimer(ITIMER_REAL,&timer,NULL)){perror("setitimer");exit(1);}
				timeout = false;
				//TCP never computes sampleRTT for retransmitted segment
				if(!retransmit)
					compute_sample_RTT(start,end);

				break;
			}
			else if(has_seq_fin(rcvpkt,ack_number-1)){//Reack last packet received
				#ifdef debug
				std::cerr << "Got a FIN! Resending FINACK with ack number: ";
				std::cerr << ack_number-1 <<std::endl;
				#endif 
				uint8_t ack_fin[HDR_SZ];
				make_pkt(sequence_number,ack_number-1,ACK,NULL,0,ack_fin,HDR_SZ);
				send(sock,ack_fin,HDR_SZ,0);
			}
			else{//strange packet
				std::cerr <<"Got unexpected packet"<<std::endl;				
			}
		}

	} while(timeout); //resend
	

	sequence_number++;
}

void rel_send(int sock, void *buf, int len)
{
	rel_send_flags(sock,buf,len,NON);
}

int rel_socket(int domain, int type, int protocol) {
	sequence_number = 0;
	ack_number = 0;
	devRTT = 0;
	estimatedRTT = 0;
	first_acks = 0;
	server = false;
	timeout = false;
	
	struct sigaction act;
	act.sa_handler = handle_sigalarm;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0; 
	
	sigaction(SIGALRM,&act,NULL);

	return socket(domain, type, protocol);
}


int rel_recv(int sock, void * buffer, size_t length) {
	uint8_t rcvpkt[MAX_PACKET];
	memset(&rcvpkt,0,MAX_PACKET);
	uint8_t sndpkt[HDR_SZ];

	struct sockaddr_in fromaddr;
	unsigned addrlen = sizeof(fromaddr);	
	int recv_count = recvfrom(sock, rcvpkt, MAX_PACKET, 0, (struct sockaddr*)&fromaddr, &addrlen);		

	// this is a shortcut to 'connect' a listening server socket to the incoming client.
	// after this, we can use send() instead of sendto(), which makes for easier bookkeeping
	if(connect(sock, (struct sockaddr*)&fromaddr, addrlen)) {
		std::cerr << "couldn't connect socket" << std::endl;
	}

	while(!has_seq(rcvpkt,ack_number)){
		make_pkt(sequence_number,ack_number-1,ACK,NULL,0,sndpkt,HDR_SZ);
		send(sock,sndpkt,HDR_SZ,0);

		memset(&rcvpkt,0,MAX_PACKET);
		recv_count = recv(sock,rcvpkt,MAX_PACKET,0);
	}	

	make_pkt(sequence_number,ack_number,ACK,NULL,0,sndpkt,HDR_SZ);
	send(sock,sndpkt,HDR_SZ,0);


	hdr_ptr hdr = (hdr_ptr)rcvpkt;
	if(hdr->flags & FIN){
		server = true;
	}

	ack_number++;

	memcpy(buffer, rcvpkt+HDR_SZ, recv_count-HDR_SZ);

	return recv_count-HDR_SZ;
}

#define TIMEOUT_CONNREFUSED (errno == EAGAIN || errno == EWOULDBLOCK || errno == ECONNREFUSED)

int rel_recv_fin(int sock) {
	uint8_t rcvpkt[HDR_SZ];
	uint8_t sndpkt[HDR_SZ];

	#ifdef debug
	std::cerr << "rel_recv_fin: seq_num: " << sequence_number;
	std::cerr << " ack_number: " << ack_number <<std::endl;
	#endif 

	int recv_count;
	while(1){
		memset(&rcvpkt,0,HDR_SZ);
		recv_count = recv(sock, rcvpkt, HDR_SZ, 0);		

		if(recv_count < 0){
			if(TIMEOUT_CONNREFUSED){
				#ifdef debug
				std::cerr << "Not waiting for FIN from server" << std::endl;
				#endif
				return 0;
			}
			else{
				perror("rel_recv_fin: recv");
				exit(1);
			}
		}
		else if(recv_count >= 0 && recv_count < HDR_SZ){
			#ifdef debug
			std::cerr << "Got strange segment, ignoring" <<std::endl;
			#endif
		}
		else if(!has_seq_fin(rcvpkt,ack_number)){
			make_pkt(sequence_number,ack_number-1,ACK,NULL,0,sndpkt,HDR_SZ);
			send(sock,sndpkt,HDR_SZ,0);
		}
		else break;
	} 

	//Got FIN, send ack and time wait
	make_pkt(sequence_number,ack_number,ACK,NULL,0,sndpkt,HDR_SZ);
	send(sock,sndpkt,HDR_SZ,0);

	struct timeval save;
	save_sockopt(sock,&save);

	struct timeval timewait;
	msec_to_timeval(TIMEWAIT,&timewait);

	setsockopt(sock,SOL_SOCKET,SO_RCVTIMEO,&timewait,sizeof(struct timeval));

	#ifdef debug
	std::cerr << "Sent fin ack" <<std::endl;
	#endif 

	while(1){
		recv_count = recv(sock,rcvpkt,HDR_SZ,0);

		if(recv_count<0){
			if(TIMEOUT_CONNREFUSED) {
				#ifdef debug
				std::cerr << "Assuming server got my fin ack" << std::endl;
				#endif
				break;
			}
			else { 
				perror("rel_recv : recv"); 
				exit(1);
			} 
		}
		else if(recv_count >= HDR_SZ && has_seq_fin(rcvpkt,ack_number)){
			#ifdef debug
			std::cerr << "Resending fin ack" <<std::endl;
			#endif 
			send(sock,sndpkt,HDR_SZ,0);		
		}
		else{
			#ifdef debug
			std::cerr << "Got strange segment, ignoring" <<std::endl;
			#endif 
		}
	}	

	restore_sockopt(sock,&save);

	ack_number++;

	return recv_count - HDR_SZ;
}

int rel_close(int sock) {
	rel_send_flags(sock,NULL,0,FIN); // send an empty packet to signify end of file

	if(!server) rel_recv_fin(sock);	

	close(sock);
}

