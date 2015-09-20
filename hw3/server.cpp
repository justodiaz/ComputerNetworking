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

#define NOPLAYER 0
#define SENDWANT 1
#define SENDCARD 2
#define INBATTLE 3

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

int Shutdown(int sockfd, int how){
	int rc;
	rc = shutdown(sockfd,how);
	if(rc < 0){
		perror("Shutdown error");
		exit(1);
	}

	return rc;
}

typedef struct {
	int state;
	int fd;
	vector<char> deck;
	int battle_card;
} Player;



class Game{
	Player player1;
	Player player2;

	void clear_fds(Player &player, Player &other){
		cout << "Client on fd " << player.fd << " misbehaved." <<endl;
		Shutdown(player.fd,SHUT_RDWR);
		
		if(other.state != NOPLAYER) Shutdown(other.fd,SHUT_RDWR);
	}

	bool valid_card(vector<char> &mydeck, char card){
		auto iter = find(mydeck.begin(),mydeck.end(),card);
		
		if(iter == mydeck.end()) return false;
		
		mydeck.erase(iter);
		return true;
	}

	void play_battle(){
		player1.battle_card %= 13;
		player2.battle_card %= 13;
		
		char result1[2] = {PLAYRESULT,0};
		char result2[2] = {PLAYRESULT,0};
		
		if(player1.battle_card > player2.battle_card)
			{ result1[1] = WIN; result2[1] = LOSE; }
		else if (player1.battle_card < player2.battle_card)
			{ result1[1] = LOSE; result2[1] = WIN; }
		else
			{ result1[1] = DRAW; result2[1] = DRAW; }
		
		Send(player1.fd,result1, sizeof result1,0);
		Send(player2.fd,result2, sizeof result2,0);
			
	}

	bool _resolve(Player &player,Player &other){
		switch(player.state){
		case SENDWANT:
		{ //should send 'want' message
			char want[2] = {0};
			Recv(player.fd,want, sizeof want,0);

			if(want[0] != WANTGAME || want[1] != 0){
				clear_fds(player,other);
				return false;
			}

			player.state = SENDCARD;

			char gamestart[27];
			gamestart[0] = GAMESTART;
			for(int i=1;i<=26;i++) gamestart[i] = player.deck[i-1];
			Send(player.fd,gamestart,sizeof gamestart,0);

			break;
		}
		case SENDCARD:
		{//playing, should send a card
			char play[2] = {0};
			Recv(player.fd,play,sizeof play,0);
			if(play[0] != PLAYCARD || !valid_card(player.deck, play[1])){
				clear_fds(player,other);
				return false;
			}

			player.battle_card = (int)play[1];	

			if(other.state == INBATTLE){
				play_battle();

				if(player.deck.empty() || other.deck.empty()) {
					cout << "Game ended.";
					Shutdown(player.fd,SHUT_RDWR);
					Shutdown(other.fd,SHUT_RDWR);
					return false;
				}

				player.state = other.state = SENDCARD;
			}
			else
				player.state = INBATTLE;

			break;	
		}
		case INBATTLE: //sending data after card already sent	
			clear_fds(player,other);
			break;

		default: i_error("Game::Resolve invalid state");

		}
		
		return true;
	}

	public:
	Game(int start_fd) : 
	player1.state(SENDWANT), player1.fd(start_fd), player1.battle_card(-1),
	player2.state(NOPLAYER), player2.fd(-1), player2.battle_card(-1)
	{
		array<char, 52> deck;
		for(int i=0;i<52;i++) deck[i] = i;

		random_shuffle(deck.begin(), deck.end());
		
		for(int i=0;i<52;i++){
			if(i<26)
				player1.deck.push_back(deck[i]);	
			else
				player2.deck.push_back(deck[i]);
		}
	}

	bool iMember(int fd) {return player1.fd == fd || player2.fd == fd;}

	bool addPlayer(int fd){
		if(player2.state != NOPLAYER) return false;

		player2.fd = fd;
		player2.state = SENDWANT;
	
		return true;
	}
	
	bool resolve(int fd){

		if(fd == player1.fd) return _resolve(player1,player2);
		else if(fd == player2.fd) return _resolve(player2,player1);
		else i_error("Game::Resolve received invalid fd"); 

	}
	

};

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
	
	FD_SET(listener, &main);

	srand( unsigned (time(0)) );
	vector<Game> games;
	for(;;){
		readfds = main;
		select(maxfd+1, &readfds, NULL, NULL, NULL);
		
		for(int i=0;i<=maxfd;i++){
			if(i == listener && FD_ISSET(listener, &readfds)){//a client is trying to connect
				int newfd = accept_player(listener);
				if(newfd > maxfd) maxfd = newfd;
				FD_SET(newfd, &main);
			}
			
			if(FD_ISSET(i,&readfds)){ //about to receive data
	//				resolve(i);
				
			}
			
		}

	}
	
	return 0;
}
