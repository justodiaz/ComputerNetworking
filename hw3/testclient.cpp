#include <iostream>
#include <cstdio>
#include <cerrno>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define WANTGAME 0
#define GAMESTART 1
#define PLAYCARD 2
#define PLAYRESULT 3

#define WIN 0
#define LOSE 1
#define DRAW 2

/*Sleep tests at different points */
#define SLPSEC 1 //seconds to sleep for
#define EXITS //will exit() after sleeping
//#define TEST1 //WantGame, after send() 1 byte
//#define TEST2 //WantGame, after send()
//#define TEST3 //WantGame, after recv()
//#define TEST4 //PlayCard, after send() 1 byte
#define TEST5 //PlayCard, after send()
//#define TEST6 //PlayCard, after recv()

/*Send bad protocol tests*/
#define BADVALUE 254 //Between 0-255
//#define BADTEST1 //WantGame byte 1
//#define BADTEST2 //WantGame byte 2
//#define BADTEST3 //PlayCard byte 1
//#define BADTEST4 //PlayCard byte 2

//Wrapper functions
ssize_t Send(int sockfd, const void*buf, size_t len, int flags){
	int sent = send(sockfd,buf,len,flags);
	if(sent < 0){
		perror("Send error");
		exit(1);
	}

	if(sent != (int)len){
		std::cerr << "Send didn't send all bytes...exiting" << std::endl;
		exit(1);
	}

	return sent;
}

ssize_t Recv(int sockfd, void *buf, size_t len, int flags){
	int partial = recv(sockfd,buf,len,flags);

	int total = 0;

	while(partial > 0){
		total += partial;
		len -= partial;
		if(len <= 0) break;
		partial = recv(sockfd,(char *)buf + partial, len, 0);
	}

	if(partial < 0) { perror("Receive failed"); exit(1); }

	return total;
}

void i_error(char const *msg){
	std::cerr << msg << std::endl;
	exit(1);
}

int main(int argc, char *argv[]){
	if (argc < 3){
		std::cerr << "Usage: " << argv[0] << " <host> <port>" << std::endl;
		exit(1);
	}

	struct addrinfo hints = {0};
	struct addrinfo *res, *rp;

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;//SOCK_STREAM, SOCK_DGRAM
	hints.ai_protocol = 0; //"any"

	std::cout << "Connecting.." << std::endl;
	int s = getaddrinfo(argv[1], argv[2], &hints, &res);

	if(s){
		if(s == EAI_SYSTEM)
			perror("getaddrinfo error");
		else
			std::cerr << "getaddrinfo error: " << gai_strerror(s) << std::endl;
			
		exit(1);
	}

	int sockfd;
	for(rp = res; rp != NULL; rp = rp->ai_next){
		sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

		if(sockfd < 0) continue;

		if(connect(sockfd, rp->ai_addr, rp->ai_addrlen) == 0) break;
		
		close(sockfd);
	} 
	
	freeaddrinfo(res);
	if (rp == NULL) i_error("Could not bind");

	std::cout << "Sending want game request..." << std::endl;

	char command[2] = {0};
	char cards[27] = {0};
	
	command[0] = WANTGAME;

#ifdef BADTEST1
	std::cout <<"Sending bad WantGame message, byte 1.." <<std::endl;
	command[0] = BADVALUE;
#endif

#ifdef BADTEST2
	std::cout <<"Sending bad WantGame message, byte 2.." <<std::endl;
	command[1] = BADVALUE;
#endif
	/* Sending one byte a time */
	Send(sockfd,command,1,0);

#ifdef TEST1
	std::cout <<"Sent 1 byte of WantGame message, sleeping.." <<std::endl;
	sleep(SLPSEC);
#ifdef EXITS
	exit(1);
#endif
#endif

	Send(sockfd,command+1,1,0);
	std::cout << "Waiting for cards..." << std::endl;

#ifdef TEST2
	std::cout <<"Sent WantGame message, sleeping.." <<std::endl;
	sleep(SLPSEC);
#ifdef EXITS
	exit(1);
#endif
#endif

	Recv(sockfd,cards,sizeof(cards),0);


	if(cards[0] != GAMESTART) i_error("Server error, now exiting.");
	
	std::cout << "Ready to play!" << std::endl;

#ifdef TEST3
	std::cout <<"Received GameStart message, sleeping.." <<std::endl;
	sleep(SLPSEC);
#ifdef EXITS
	exit(1);
#endif
#endif

	int score = 0;
	
	char const *suite[] = {"Clubs","Diamonds","Hearts","Spades"};
	char const *face[] = {"Two","Three","Four","Five","Six","Seven",
				   "Eight","Nine","Ten","Jack","Queen","King","Ace"};


	for(int i = 1; i<27; i++){

		command[0] = PLAYCARD;
		command[1] = cards[i];

#ifdef BADTEST3
	std::cout <<"Sending bad PlayCard message, byte 1.." <<std::endl;
	command[0] = BADVALUE;
#endif

#ifdef BADTEST4
	std::cout <<"Sending bad PlayCard message, byte 2.." <<std::endl;
	command[1] = BADVALUE;
#endif

		int idx_suite = cards[i]/13;
		int idx_face = cards[i]%13;
		
		std::cout << "Playing " << face[idx_face] << " of " << suite[idx_suite] << ": ";
 
		/* Sending one byte a time */
		Send(sockfd,command,1,0);
#ifdef TEST4
	std::cout <<"Sent 1 byte of PlayCard message, sleeping.." <<std::endl;
	sleep(SLPSEC);
#ifdef EXITS
	exit(1);
#endif
#endif
		Send(sockfd,command+1,1,0);


#ifdef TEST5
	std::cout <<"Sent PlayCard message, sleeping.." <<std::endl;
	sleep(SLPSEC);
#ifdef EXITS
	exit(1);
#endif
#endif

		Recv(sockfd,command,sizeof(command),0);
		if(command[0] != PLAYRESULT) i_error("Server error, now exiting.");

#ifdef TEST6
	std::cout <<"Received PlayResult message, sleeping.." <<std::endl;
	sleep(SLPSEC);
#ifdef EXITS
	exit(1);
#endif
#endif
		switch(command[1]){
			case WIN:
				score++;
				std::cout << "Battle won!" << std::endl;
				break;
			case LOSE:
				score--;
				std::cout << "Battle lost!" << std::endl;
				break;
			case DRAW:
				std::cout << "Battle draw!" << std::endl;
				break;
			default:
				i_error("Server error, now exiting.");
		}	
	}

	shutdown(sockfd, SHUT_RDWR);		

	if(score > 0) std::cout << "You won the war!" << std::endl;
	else if (score < 0) std::cout << "You lost the war!" << std::endl;
	else std::cout << "War ended in a draw!" << std::endl;

	return 0;
}
