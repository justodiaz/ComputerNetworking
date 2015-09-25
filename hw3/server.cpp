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
#include "wrappers.h"
#include "game.h"

#define BACKLOG 500

using namespace std;

int acceptPlayer(int listener){	
	int newfd;
	struct sockaddr_storage a_client;
	socklen_t s_client = sizeof a_client;
	
	newfd = Accept(listener, (struct sockaddr *) &a_client, &s_client);
	cout << "Client connected." << endl;	

	return newfd;
}

void addToGame(vector<Game> &games,int newfd){
	auto iter = games.begin();
	for(; iter != games.end(); ++iter){
		if(iter->addPlayer(newfd)) break;
	}

	if(iter == games.end())
		games.push_back(Game(newfd));

}

int main(int argc, char **argv){

	if(argc < 2)
		i_error(string("Usage: ") + argv[0] + " <port>");

	struct addrinfo hints = {0};
	struct addrinfo *res;

	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;//SOCK_STREAM, SOCK_DGRAM
	hints.ai_protocol = 0; //"any"

	cout << "Starting.." << endl;
	Getaddrinfo(NULL, argv[1], &hints, &res);

	int listener = Socket(res->ai_family, res->ai_socktype, res->ai_protocol);

	Bind(listener, res->ai_addr, res->ai_addrlen);

	freeaddrinfo(res);

	Listen(listener, BACKLOG);

	cout << "Ready.." << endl;

	int maxfd = listener;

	fd_set master, readfds;

	FD_ZERO(&master);
	FD_ZERO(&readfds);
	
	FD_SET(listener, &master);

	srand( unsigned (time(0)) );
	vector<Game> games;

	for(;;){
		readfds = master;

		Select(maxfd+1, &readfds, NULL, NULL, NULL);
		
		for(int i=0;i<=maxfd;i++){
			if(FD_ISSET(i,&readfds)){
				if(i == listener){//a client is trying to connect
					int newfd = acceptPlayer(listener);

					addToGame(games,newfd);
					if(newfd > maxfd) maxfd = newfd;
					FD_SET(newfd, &master);
				}
				
				else{ //about to receive data
					auto iter = games.begin();
					auto end = games.end(); //since games.erase() modifies games.end()
					for(; iter<end; ++iter){
						if(iter->isMember(i)){
							
							int result = iter->updateGame(i);
		
							int fd1 = iter->fd1();
							int fd2 = iter->fd2();

							bool close_game = false;
							switch(result)
							{
							case GAMEON: break;
							case GAMEERROR:
								cout << "Client misbehaved. Closed game and fds." << endl;
								close_game = true;
								break;
							case GAMEEND:
								cout << "A game was completed." << endl;
								close_game = true;
								break;
							case BADFD:
								cout << "Error: Bad fd passed to updateGame." << endl;
							default: i_error("Error: updateGame");
							}

							if(close_game){
								if(fd1 >= 0) {
									//Shutdown(fd1,SHUT_RDWR); //Weird behavior when client ctrl-c
									Close(fd1);
									FD_CLR(fd1, &master);
								}
								if(fd2 >= 0) {
									//Shutdown(fd2,SHUT_RDWR);
									Close(fd2);
									FD_CLR(fd2, &master);
								}
								games.erase(iter);
							}
						
							break; //stop searching for the game the fd belongs in
						}
					}

					if(iter == end) i_error("Error: client fd socket has data but not in a game.");
					
				}//else
			}//if(FD_ISSET..
		}//for(int i=0..
	}//for(;;)
	
	exit(1);//Should never reach.
}

