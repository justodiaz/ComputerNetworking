#include <iostream>
#include <string>
#include <cstdio>
#include <cerrno>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
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

#define BACKLOG 100

using namespace std;

void i_error(string msg){
	cerr << msg << std::endl;
	exit(1);
}

//Wrapper functions
ssize_t Send(int sockfd, const void*buf, size_t len, int flags){
	int sent = send(sockfd,buf,len,flags);
	if(sent < 0){
		perror("Send error");
		exit(1);
	}

	if(sent != (int)len)
		i_error("Send didn't send all bytes...exiting");

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

	if(partial < 0){ 
		perror("Receive failed"); 
		exit(1); 
	}

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

int accept_player(int listener){	
	int newfd;
	struct sockaddr_storage a_client;
	socklen_t s_client;
	
	newfd = Accept(listener, (struct sockaddr *) &a_client, &s_client);
	cout << "Client connected." << endl;	

	return newfd;
}

verify_request(char *command){
		std::cout << "Player #"<<player_num<<" confirmed." << std::endl;
	else
		i_error("Player confirmation failed: Wrong protocol message.");

class Game{
	int state1; //verifying players or playing
	int state2; //verifying players or playing
	int fd1;
	int fd2;
	array<char, 52> deck;
	vector<char> deck1;
	vector<char> deck2;
	public:
	Game(int start_fd){
		fd1 = start_fd;
		state1 = 1;
		state2 = 0;
		for(int i=0;i<52;i++) deck[i] = i;

		srand( unsigned (time(0)) );
		random_shuffle(deck.begin(), deck.end());
		
		for(int i=0;i<52;i++){
			if(i<26)
				deck1.push_back(deck[i]);	
			else
				deck2.push_back(deck[i]);
		}
	}

	bool iMember(int fd) {return fd1 == fd || fd2 == fd;}

	bool addPlayer(int fd){
		if(state2 != 0) return false;

		fd2 = fd;
		state2 = 1;
	
		return true;
	}
	
	void resolve(int fd){

		if(fd == fd1){
			switch(state1){
				case 1:
					char want[2] = {0};
					Recv(fd,want, sizeof want,0);
					if(want[0] == WANTGAME && want[1] == 0){
						state1 = 2;
						char gamestart[27];
						gamestart[0] = GAMESTART;
						 
							
					}
					break;
				case 2:

					break;
				default: i_error("Game::Resolve invalid state");

			}		
		}
		else if(fd == fd2){



		}
		else i_error("Game::Resolve received invalid fd"); 

	}
	

}

int main(int argc, char **argv){

	if(argc < 2)
		i_error(string("Usage: ") + argv[0] + " <port>");

	
	struct addrinfo hints = {0};
	struct addrinfo *res, *rp;

	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;//SOCK_STREAM, SOCK_DGRAM
	hints.ai_protocol = 0; //"any"

	cout << "Starting.." << endl;
	int s = getaddrinfo(NULL, argv[1], &hints, &res);

	if(s){
		if(s == EAI_SYSTEM){
			perror("getaddrinfo error");
			exit(1);
		}

		i_error(string("getaddrinfo error: ") + gai_strerror(s));
	}

	int listener;
	for(rp = res; rp != NULL; rp = rp->ai_next){
		listener = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

		if(listener < 0) continue;

		if(bind(listener, rp->ai_addr, rp->ai_addrlen) == 0) break;
		
		close(listener);
	} 

	freeaddrinfo(res);
	if (rp == NULL) i_error("Could not bind");

	cout << "Ready.." << endl;

	Listen(listener, BACKLOG);

	int maxfd = listener;
	
	fd_set main, readfds;
	
	FD_SET(listener, main);

	vector<Games> games;
	for(;;){
		readfds = main;
		select(maxfd+1, readfds, NULL, NULL, NULL);
		
		for(int i=0;i<=maxfd;i++)
			if(i == listener && FD_ISSET(listener, readfds)){//a client is trying to connect
				int newfd = accept_player(listener);
				FD_SET(newfd, main);
			}
			
			if(FD_ISSET(i,readfds)){ //about to receive data
					resolve(i);
				
			}
			
			

	}
	
	return 0;
}
