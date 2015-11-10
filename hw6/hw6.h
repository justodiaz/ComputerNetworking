#include <sys/time.h>

#define NON 0x00
#define FIN 0x01
#define SYN 0x02
#define ACK 0x10

struct hw6_hdr {
	uint32_t sequence_number;
	uint32_t ack_number;
	uint8_t flags;
};

#define INIT_TO 1000 //msec, initial estimated rtt is 1 sec
#define MAX_PACKET 1400
#define MAX_SEGMENT (MAX_PACKET-sizeof(struct hw6_hdr))
#define HDR_SZ (sizeof(struct hw6_hdr))
#define diff(x,y) ((x)< (y) ? (y)-(x) : (x)-(y)) 

typedef struct hw6_hdr* hdr_ptr;

int rel_socket(int domain, int type, int protocol);
int rel_connect(int socket,struct sockaddr_in *toaddr,int addrsize);
void rel_send(int sock, void *buf, int len);
int rel_recv(int sock, void * buffer, size_t length);
int rel_close(int sock);
int rel_rtt(int sock);

int timeval_to_msec(struct timeval *t);
void msec_to_timeval(int millis, struct timeval *out_timeval);
int current_msec();

