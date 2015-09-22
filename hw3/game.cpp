#include <algorithm>
#include "wrappers.h"
#include "game.h"

bool Game::valid_card(vector<char> &mydeck, char card){
	auto iter = find(mydeck.begin(),mydeck.end(),card);
	
	if(iter == mydeck.end()) return false;
	
	mydeck.erase(iter);
	return true;
}

void Game::play_battle(){
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

int Game::_updateGame(Player &player,Player &other){
	switch(player.state){
	case SENDWANT:
	{ //should send 'want' message
		int amnt = Recv(player.fd,player.buf+player.buf_i, BUFSZ-player.buf_i,0);
		if(amnt == 0) return GAMEERROR; //client closed their connection
		
		player.buf_i += amnt;
		if(player.buf_i < BUFSZ) return GAMEON; //not enough according to protocol
		
		player.buf_i = 0;
		
		if(player.buf[0] != WANTGAME || player.buf[1] != 0)
			return GAMEERROR;

		player.state = SENDCARD;

		char gamestart[27];
		gamestart[0] = GAMESTART;
		for(int i=1;i<=26;i++) gamestart[i] = player.deck[i-1];
		Send(player.fd,gamestart,sizeof gamestart,0);

		break;
	}
	case SENDCARD:
	{//playing, should send a card
		int amnt = Recv(player.fd,player.buf+player.buf_i, BUFSZ-player.buf_i,0);
		if(amnt == 0) return GAMEERROR;
		
		player.buf_i += amnt;
		if(player.buf_i < BUFSZ) return GAMEON;

		player.buf_i = 0;

		if(player.buf[0] != PLAYCARD || !valid_card(player.deck, player.buf[1]))
			return GAMEERROR;

		player.battle_card = (int)player.buf[1];	

		if(other.state == INBATTLE){
			play_battle();

			if(player.deck.empty() || other.deck.empty()) //if one is empty, ther other is too
				return GAMEEND;

			player.state = other.state = SENDCARD;
		}
		else
			player.state = INBATTLE;

		break;	
	}
	case INBATTLE: //sending data after card already sent	
		return GAMEERROR;
		break;

	default: i_error("updateGame: invalid state.");

	}
	
	return GAMEON;
}

Game::Game(int start_fd) : 
	player1{SENDWANT, start_fd, -1, {-1,-1}, 0},
	player2{NOPLAYER, -1, -1, {-1,-1}, 0} 
	{
		array<char, DECKSIZE> deck;
		for(int i=0;i<DECKSIZE;i++) deck[i] = i;

		random_shuffle(deck.begin(), deck.end());
		
		int halfdeck = DECKSIZE/2;
		for(int i=0;i<DECKSIZE;i++){
			if(i<halfdeck)
				player1.deck.push_back(deck[i]);	
			else
				player2.deck.push_back(deck[i]);
		}
	}

bool Game::addPlayer(int fd){
	if(player2.state != NOPLAYER) return false;

	player2.fd = fd;
	player2.state = SENDWANT;

	return true;
}

int Game::updateGame(int fd){
	if(fd == player1.fd) return _updateGame(player1,player2);
	if(fd == player2.fd) return _updateGame(player2,player1);

	return BADFD;
}
int Game::fd1(){ 
	if(player1.state == NOPLAYER) return -1;
	return player1.fd;
}

int Game::fd2(){ 
	if(player2.state == NOPLAYER) return -1;
	return player2.fd;
}
