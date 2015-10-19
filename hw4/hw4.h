#define BUFSIZE 500
typedef struct addrinfo saddrinfo;
typedef struct sockaddr_storage sss;

typedef struct icache{
	char hostname[BUFSIZE];
	uint16_t type;
	uint8_t response[UDP_RECV_SIZE];
	int resp_sz;
	time_t TTL;
	time_t timestamp;
	struct icache *next;
} cache;

typedef struct {
	char name[BUFSIZE];
	struct dns_rr rr;
	uint8_t value[BUFSIZE];
} answer_rr;	

int resolve_name(int sock, uint8_t * request, int packet_size, uint8_t * response, sss * nameservers, int nameserver_count);
void update_TTL(uint8_t * response, uint32_t TTL);
