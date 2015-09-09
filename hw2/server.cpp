#include <iostream>
#include <cstdio>
#include <cerrno>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <array>
#include <algorithm>

#define WANTGAME 0
#define GAMESTART 1
#define PLAYCARD 2
#define PLAYRESULT 3

#define WIN 0
#define LOSE 1
#define DRAW 2

#define BACKLOG 2

//Wrapper functions
ssize_t Send(int sockfd, const void*buf, size_t len, int flags){
	int sent = send(sockfd,buf,len,flags);
	if(sent < 0){
		perror("Send error");
		exit(0);
	}

	if(sent != (int)len){
		std::cerr << "Send didn't send all bytes...exiting" << std::endl;
		exit(0);
	}

	return sent;
}

ssize_t Recv(int sockfd, void *buf, size_t len, int flags){
	int partial = recv(sockfd,buf,len,flags);

	int total = 0;

	while(partial > 0){
		total += partial;
		len -= partial;
		partial = recv(sockfd,(char *)buf + partial, len < 0 ? 0 : len, 0);
	}

	if(partial < 0) { perror("Receive failed"); exit(0); }

	return total;
}

void Listen(int s, int backlog) 
{
    int rc;

    if ((rc = listen(s,  backlog)) < 0){
		perror("Listen error");
		exit(0);
	}
}

int Accept(int s, struct sockaddr *addr, socklen_t *addrlen) 
{
    int rc;

    if ((rc = accept(s, addr, addrlen)) < 0){
		perror("Accept error");
		exit(0);
	}

    return rc;
}


void i_error(char const *msg){
	std::cerr << msg << std::endl;
	exit(0);
}

int main(int argc, char *argv[]){
	if (argc < 2){
		std::cerr << "Usage: " << argv[0] << " <port>" << std::endl;
		exit(0);
	}

	struct addrinfo hints = {0};
	struct addrinfo *res, *rp;

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;//SOCK_STREAM, SOCK_DGRAM
	hints.ai_protocol = 0; //"any"

	std::cout << "Starting.." << std::endl;
	int s = getaddrinfo(NULL, argv[1], &hints, &res);

	if(s){
		if(s == EAI_SYSTEM)
			perror("getaddrinfo error");
		else
			std::cerr << "getaddrinfo error: " << gai_strerror(s) << std::endl;
			
		exit(0);
	}

	int sockfd;
	for(rp = res; rp != NULL; rp = rp->ai_next){
		sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

		if(sockfd < 0) continue;

		if(bind(sockfd, rp->ai_addr, rp->ai_addrlen) == 0) break;
		
		close(sockfd);
	} 
	
	freeaddrinfo(res);
	if (rp == NULL) i_error("Could not bind");

	std::cout << "Ready.." << std::endl;

	struct sockaddr_storage a_client1, a_client2; //socket addresses
	socklen_t s_client1 = sizeof a_client1;
	socklen_t s_client2 = sizeof a_client2; //sizes
	int client1, client2; //fds

    char command[2] = {0};
	char cards[27] = {0};

	Listen(sockfd, BACKLOG);
	
	std::cout << "Accepting connection..." << std::endl;	
	client1 = Accept(sockfd, (struct sockaddr *) &a_client1, &s_client1);
	std::cout << "Accepted..." << std::endl;	

	Recv(client1,command, sizeof command,0);

    if(command[0] == WANTGAME && command[1] == 0)
		std::cout << "Player 1 accepted." << std::endl;
	else
		i_error("Client connected to did not follow protocol");
		
	client2 = Accept(sockfd, (struct sockaddr *) &a_client2, &s_client2);

	Recv(client2,command, sizeof command, 0);

    if(command[0] == WANTGAME && command[1] == 0)
		std::cout << "Player 2 accepted." << std::endl;
	else
		i_error("Client connected to did not follow protocol");
	
	std::cout <<"Dealing cards." << std::endl;

	std::array<char, 52> deck;
	for(int i=0;i<52;i++) deck.at(i) = i;

	std::random_shuffle(deck.begin(), deck.end());

	cards[0] = GAMESTART;

	int i=0;
	for(int j=1;i<=27;j++,i++) cards[j] = deck.at(i);
	Send(client1,cards,sizeof cards,0);

	for(int j=1;i<=27;j++,i++) cards[j] = deck.at(i);
	Send(client2,cards,sizeof cards,0);

	
	/*
	std::cout << "Sending want game request..." << std::endl;
	
	command[0] = WANTGAME;

	Send(sockfd,command,sizeof(command),0);

	Recv(sockfd,cards,sizeof(cards),0);

	if(cards[0] != GAMESTART) i_error("Server error, now exiting.");

	int score = 0;
	for(int i = 1; i<27; i++){

		command[0] = PLAYCARD;
		command[1] = cards[i];
 
		Send(sockfd,command,sizeof(command),0);

		Recv(sockfd,command,sizeof(command),0);

		if(command[0] != PLAYRESULT) i_error("Server error, now exiting.");

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
*/
	return 0;
}
