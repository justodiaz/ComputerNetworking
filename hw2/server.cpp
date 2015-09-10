//Justo Diaz Esquivel
//CS450 HW2
//War Card game server
#include <iostream>
#include <cstdio>
#include <cerrno>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <array>
#include <vector>
#include <algorithm>
#include <ctime>
#include <cstdlib>

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

void Listen(int s, int backlog) 
{
    int rc;

    if ((rc = listen(s,  backlog)) < 0){
		perror("Listen error");
		exit(1);
	}
}

int Accept(int s, struct sockaddr *addr, socklen_t *addrlen) 
{
    int rc;

    if ((rc = accept(s, addr, addrlen)) < 0){
		perror("Accept error");
		exit(1);
	}

    return rc;
}


void i_error(char const *msg){
	std::cerr << msg << std::endl;
	exit(1);
}

int accept_player(int sockfd, int player_num){	
	int newfd;
	struct sockaddr_storage a_client;
	socklen_t s_client;
	
	char command[2] = {0};
	std::cout << "Accepting connection #" << player_num <<"..." << std::endl;	
	newfd = Accept(sockfd, (struct sockaddr *) &a_client, &s_client);
	std::cout << "Accepted." << std::endl;	

	std::cout << "Waiting for player confirmation..." << std::endl;
	Recv(newfd,command, sizeof command,0);

	if(command[0] == WANTGAME && command[1] == 0)
		std::cout << "Player #"<<player_num<<" confirmed." << std::endl;
	else
		i_error("Player confirmation failed: Wrong protocol message.");

	return newfd;
}

void validate_card(std::vector<char> &p, char card){
	auto iter = std::find(p.begin(),p.end(),card);
	if(iter == p.end())
		i_error("Client error");
	else
		p.erase(iter);

}

int main(int argc, char *argv[]){
	if (argc < 2){
		std::cerr << "Usage: " << argv[0] << " <port>" << std::endl;
		exit(1);
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
			
		exit(1);
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

	int client1, client2; //fds

	Listen(sockfd, BACKLOG);

	client1 = accept_player(sockfd, 1);
	client2 = accept_player(sockfd, 2);

	std::cout <<"Dealing cards..." << std::endl;

	std::array<char, 52> deck;
	for(int i=0;i<52;i++) deck[i] = i;

	std::srand( unsigned (std::time(0)) );

	std::random_shuffle(deck.begin(), deck.end());

	char cards[27] = {0};
	cards[0] = GAMESTART;

	int i=0;

	std::vector<char> p1_cards;

	for(int j=1;j<=26;j++,i++) {
		cards[j] = deck[i];
		p1_cards.push_back(deck[i]);
	}
	Send(client1,cards,sizeof cards,0);

	std::vector<char> p2_cards;

	for(int j=1;j<=26;j++,i++){
		cards[j] = deck[i];
		p2_cards.push_back(deck[i]);
	}
	Send(client2,cards,sizeof cards,0);

	std::cout <<"Playing..." << std::endl;

    char command[2] = {0};
	int p1, p2;
	for(int i=0;i<26;i++){
		Recv(client1,command,sizeof command,0);
		
		if(command[0] != PLAYCARD) i_error("Client error");

		p1 = (int)command[1];

		validate_card(p1_cards,(char)p1);		
		
		Recv(client2,command,sizeof command,0);
		
		if(command[0] != PLAYCARD) i_error("Client error");

		p2 = (int)command[1];

		validate_card(p2_cards,(char)p2);		

		p1 %= 13;
		p2 %= 13;

		command[0] = PLAYRESULT;
		if(p1 > p2) command[1] = WIN;
		else if(p1 < p2) command[1] = LOSE;
		else command[1] = DRAW;

		Send(client1,command, sizeof command,0);

		if(command[1] == WIN) command[1] = LOSE;
		else if(command[1] == LOSE) command[1] = WIN;
		else command[1] = DRAW;

		Send(client2,command,sizeof command,0);
	}

	shutdown(client1, SHUT_RDWR);
	shutdown(client2, SHUT_RDWR);
	shutdown(sockfd, SHUT_RDWR);
		
	std::cout <<"Server exiting..." << std::endl;
	return 0;
}
