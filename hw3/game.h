//War Protocol
#define WANTGAME 0
#define GAMESTART 1
#define PLAYCARD 2
#define PLAYRESULT 3

#define WIN 0
#define LOSE 1
#define DRAW 2

//Player States
#define NOPLAYER 0
#define SENDWANT 1
#define SENDCARD 2
#define INBATTLE 3

//GameUpdate signals
#define GAMEON 1
#define GAMEERROR 2
#define GAMEEND 3
#define BADFD 4

//Other
#define DECKSIZE 52
#define BUFSZ 2

typedef struct {
	int state;
	int fd;
	int battle_card;
	char buf[BUFSZ];
	int buf_i;
	vector<char> deck;
} Player;

class Game{
	Player player1;
	Player player2;

	bool valid_card(vector<char> &mydeck, char card);
	void play_battle();
	int _updateGame(Player &player,Player &other);

	public:
	Game(int start_fd); 
	bool isMember(int fd) {return player1.fd == fd || player2.fd == fd;}
	bool addPlayer(int fd);
	int updateGame(int fd);
	int fd1(); 
	int fd2(); 
};
