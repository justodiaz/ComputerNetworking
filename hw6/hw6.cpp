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
uint32_t first_acks; //Don't use estimatedRTT and devRTT until after two samples
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
	return 0;	

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

bool has_seq(void *rcvpkt, uint32_t seq_num, uint8_t flags){
	hdr_ptr hdr = (hdr_ptr)rcvpkt;
#ifdef debug	
	std::cerr << "Got packet " << ntohl(hdr->sequence_number);
	std::cerr << ", Expected " << seq_num << std::endl;
#endif

	return (hdr->flags & flags) == flags && ntohl(hdr->sequence_number) == seq_num;	
}

void compute_sample_RTT(uint32_t init, uint32_t left){
	uint32_t sampleRTT;

	sampleRTT = init - left;	
	
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

void Setitimer(int which, const struct itimerval *new_value, struct itimerval *old_value){
	if(setitimer(which,new_value,old_value)){
		perror("setitimer");
		exit(1);
	}
}
void Getitimer(int which, struct itimerval *curr_value){
	if(getitimer(which,curr_value)){
		perror("getitimer");
		exit(1);
	}
}

void set_handler(struct sigaction *old){
	struct sigaction act;
	act.sa_handler = handle_sigalarm;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0; 
	sigaction(SIGALRM,&act,old);
}

void rel_send_flags(int sock, void *buf, int len, uint8_t flags){
	uint8_t sndpkt[MAX_PACKET];
	uint8_t rcvpkt[MAX_PACKET];
	bool retransmit = false;
	uint32_t timeoutInterval;
	struct itimerval timer = {0};

	struct sigaction old;
	set_handler(&old);

	/* TCP, only use estimatedRTT and devRTT after two acks
	   First ack RTT is set as estimatedRTT */
	if(first_acks < 2) 
		timeoutInterval = INIT_TO;
	else 
		timeoutInterval = estimatedRTT + 4*devRTT;

	#ifdef debug
	std::cerr <<"timeoutInterval: " << timeoutInterval <<std::endl;
	#endif

//	msec_to_timeval(timeoutInterval,&timer.it_value);

	make_pkt(sequence_number,ack_number,flags,buf,(size_t)len,sndpkt,MAX_PACKET);

	do{
		memset(rcvpkt,0,MAX_PACKET);
		timeout = false;

		#ifdef debug
		std::cerr <<"Sending packet" << std::endl;
		#endif

		msec_to_timeval(timeoutInterval,&timer.it_value);

		send(sock, sndpkt, HDR_SZ+len, 0);
		//Setitimer(ITIMER_REAL,&timer,NULL);

		while(1){
			if(timer.it_value.tv_sec == 0 && timer.it_value.tv_usec < 1000)
				timer.it_value.tv_usec = 1000;//safety

			Setitimer(ITIMER_REAL,&timer,NULL);
			int ret = recv(sock, rcvpkt, MAX_PACKET, 0);
			Getitimer(ITIMER_REAL,&timer);

			#ifdef debug
			std::cerr <<"Time on clock: " << timeval_to_msec(&timer.it_value) <<std::endl;
			#endif
			
			if(ret<0){
				if(errno == EINTR && timeout) {
					//TCP would double timeout interval after each timeout
					#ifdef debug
					std::cerr << "Timeout OK" <<std::endl;
					#endif	
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
				//TCP never computes sampleRTT for retransmitted segment
				if(!retransmit)
					compute_sample_RTT(timeoutInterval,timeval_to_msec(&timer.it_value));

				//stop timer
				timer = {{0,0},{0,0}};
				Setitimer(ITIMER_REAL,&timer,NULL);
				timeout = false;
				break;
			}
			else if(has_seq(rcvpkt,ack_number-1,NON)){//Reack last packet received
				#ifdef debug
				std::cerr << "Resending ACK with ack number: ";
				std::cerr << ack_number-1 <<std::endl;
				#endif 
				uint8_t ack[HDR_SZ];
				make_pkt(sequence_number,ack_number-1,ACK,NULL,0,ack,HDR_SZ);
				send(sock,ack,HDR_SZ,0);
			}
			else{//strange packet
				#ifdef debug
				std::cerr <<"rel_send_flags: Got unexpected packet"<<std::endl;				
				#endif
			}
		}

	} while(timeout); //resend
	
	sigaction(SIGALRM,&old,NULL);

	sequence_number++;
}

void rel_send(int sock, void *buf, int len){
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

	return socket(domain, type, protocol);
}

int rel_recv_flags(int sock, void * buffer, size_t length, uint8_t flags) {
	uint8_t rcvpkt[MAX_PACKET];
	memset(&rcvpkt,0,MAX_PACKET);
	uint8_t sndpkt[HDR_SZ];

	struct sockaddr_in fromaddr;
	unsigned addrlen = sizeof(fromaddr);	
	int recv_count = recvfrom(sock, rcvpkt, MAX_PACKET, 0, (struct sockaddr*)&fromaddr, &addrlen);		
	// this is a shortcut to 'connect' a listening server socket to the incoming client.
	// after this, we can use send() instead of sendto(), which makes for easier bookkeeping
	if(connect(sock, (struct sockaddr*)&fromaddr, addrlen)){
		#ifdef debug
		std::cerr << "couldn't connect socket" << std::endl;
		#endif
	}

	while(1){
		if(recv_count < 0){
			if((errno == EINTR && timeout) || errno == ECONNREFUSED){
				#ifdef debug
				std::cerr << "Connection lost. Not receiving" << std::endl;
				#endif
				return 0;
			}
			else{
				perror("rel_recv_flags: recv");
				exit(1);
			}
		}
		else if(recv_count >= 0 && recv_count < HDR_SZ){
			#ifdef debug
			std::cerr << "rel_recv_flags: Got strange segment, ignoring" <<std::endl;
			#endif
		}
		else if(!has_seq(rcvpkt,ack_number,flags)){
			#ifdef debug
			std::cerr << "rel_recv_flags: resending ack" << std::endl;
			#endif

			make_pkt(sequence_number,ack_number-1,ACK,NULL,0,sndpkt,HDR_SZ);
			send(sock,sndpkt,HDR_SZ,0);
		}
		else break;

		memset(&rcvpkt,0,MAX_PACKET);
		recv_count = recv(sock, rcvpkt, MAX_PACKET, 0);		
	} 

	make_pkt(sequence_number,ack_number,ACK,NULL,0,sndpkt,HDR_SZ);
	send(sock,sndpkt,HDR_SZ,0);
	
	/* One side of connection should not go into timewait state */
	hdr_ptr hdr = (hdr_ptr)rcvpkt;
	if(hdr->flags & FIN){
		server = true;
	}

	ack_number++;

	memcpy(buffer, rcvpkt+HDR_SZ, recv_count-HDR_SZ);

	return recv_count-HDR_SZ;
}

int rel_recv(int sock, void * buffer, size_t length) {
	return rel_recv_flags(sock,buffer,length,NON);
}

int rel_close(int sock) {
	rel_send_flags(sock,NULL,0,FIN); // send an empty packet to signify end of file

	if(!server) {
		rel_recv_flags(sock,NULL,0,FIN);	

		#ifdef debug
		std::cerr << "Sent fin ack" <<std::endl;
		#endif 
		uint8_t rcvpkt[HDR_SZ];
		int recv_count;

		struct sigaction old;
		set_handler(&old);

		struct itimerval timewait = {0};
		msec_to_timeval(TIMEWAIT,&timewait.it_value);

		while(1){
			Setitimer(ITIMER_REAL,&timewait,NULL);
			recv_count = recv(sock,rcvpkt,HDR_SZ,0);

			if(recv_count<0){
				if((errno == EINTR && timeout) || errno == ECONNREFUSED) {
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
			else if(recv_count >= HDR_SZ && has_seq(rcvpkt,ack_number-1,FIN)){
				#ifdef debug
				std::cerr << "Resending FIN ACK" <<std::endl;
				#endif 
				uint8_t ack_fin[HDR_SZ];
				make_pkt(sequence_number,ack_number-1,ACK,NULL,0,ack_fin,HDR_SZ);
				send(sock,ack_fin,HDR_SZ,0);
			}
			else{
				#ifdef debug
				std::cerr << "Timewait: Got strange segment, ignoring" <<std::endl;
				#endif 
			}
		}	

		sigaction(SIGALRM,&old,NULL);
	}

	close(sock);
	
	return 0;
}

