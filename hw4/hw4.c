#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include "dns.h"


typedef struct addrinfo saddrinfo;
typedef struct sockaddr_storage sss;
int root_server_count;
sss root_servers[255];
static int debug=0;

struct cache{
	char hostname[255];
	uint8_t response[UDP_RECV_SIZE];
	int resp_sz;
	time_t TTL;
	struct cache *next;
};

struct cache *head = NULL;

void add_cache(char *hostname, uint8_t* response, int resp_sz, time_t TTL){
		struct cache *ptr = head;
		struct cache *prev = NULL;

		int add = 1;

		while(ptr != NULL){
			if(strcmp(hostname,ptr->hostname) == 0){
				ptr->TTL = ptr->TTL > TTL ? TTL : ptr->TTL;
				add = 0;
				break;
			}

			prev = ptr;
			ptr = ptr->next;
		}
			
		if(add){
			struct cache *newCache = (struct cache *)malloc(sizeof(struct cache));
			strcpy(newCache->hostname,hostname);
			memcpy(newCache->response,response,resp_sz);
			newCache->resp_sz = resp_sz;
			newCache->TTL = TTL+time(NULL);
			newCache->next = NULL;
			
			if(debug) printf("Added cache with TTL of %d\n",(unsigned)newCache->TTL);

			if(prev == NULL) head = newCache;
			else prev->next = newCache;
		}
}


int check_cache(uint8_t *request, uint8_t *response){

		struct dns_hdr *req_hdr = (struct dns_hdr*)request;
		uint8_t *req_name = request + sizeof(struct dns_hdr);
		char name[255];
		from_dns_style(request,req_name,name);

		int sz = 0;
		struct cache *ptr = head;
		struct cache *prev = NULL;
		
		while(ptr != NULL){
			if(strcmp(ptr->hostname,name) == 0){


				if(ptr->TTL > time(NULL)){ //not expired

					if(debug) printf("Cache hit on %s\n", name);
					
					sz = ptr->resp_sz;
					memcpy(response,ptr->response,sz);
					
					struct dns_hdr* resp_hdr = (struct dns_hdr*)response;
					
					resp_hdr->id = req_hdr->id;
				}
				else{ //expired so erase it
					if(debug) printf("%s in cache, but expired TTL\n", name);

					struct cache *temp = ptr->next;
					free(ptr);

					if(prev != NULL) prev->next = temp;
					else head = temp;

				}
			}
				
			prev = ptr;
			ptr = ptr->next;
		}

		return sz;
}

int resolve_name(int sock, uint8_t * request, int packet_size, uint8_t * response, sss * nameservers, int nameserver_count);

void usage() {
  printf("Usage: hw4 [-d] [-p port]\n\t-d: debug\n\t-p: port\n");
  exit(1);
}

/* returns: true if answer found, false if not.
 * side effect: on answer found, populate result with ip address.
 */
int extract_answer(uint8_t * response, sss * result){
  // parse the response to get our answer
  struct dns_hdr * header = (struct dns_hdr *) response;
  uint8_t * answer_ptr = response + sizeof(struct dns_hdr);

  memset(result,0,sizeof(sss));
  
  // now answer_ptr points at the first question.
  int question_count = ntohs(header->q_count);
  int answer_count = ntohs(header->a_count);
  int auth_count = ntohs(header->auth_count);
  int other_count = ntohs(header->other_count);


  if(debug)
    printf("****** In extract answer *********\n");
  // if we didn't get an answer, just quit
  if (answer_count == 0 ){
	printf("Error in extract_answer, no answers\n");
    return 0;
  }

  // skip questions
  for(int q=0; q<question_count; q++){
    char string_name[255];
    memset(string_name,0,255);
    int size=from_dns_style(response, answer_ptr,string_name);
    answer_ptr+=size;
    answer_ptr+=4;
  }

  if(debug)
    printf("Got %d+%d+%d=%d resource records total.\n",answer_count,auth_count,other_count,answer_count+auth_count+other_count);

  if(answer_count+auth_count+other_count>50){
    printf("ERROR: got a corrupt packet\n");
    return -1;
  }

  /*
   * accumulate authoritative nameservers to a list so we can recurse through them
   */
  for(int a=0; a<answer_count;a++)
  {
    // first the name this answer is referring to
    char string_name[255];
    int dnsnamelen=from_dns_style(response,answer_ptr,string_name);
    answer_ptr += dnsnamelen;

    // then fixed part of the RR record
    struct dns_rr* rr = (struct dns_rr*)answer_ptr;
    answer_ptr+=sizeof(struct dns_rr);

    //A record
    if(htons(rr->type)==RECTYPE_A)
    {
      if(debug)
        printf("The name %s resolves to IP addr: %s\n",
            string_name,
            inet_ntoa(*((struct in_addr *)answer_ptr)));
      //if it's in the answer section, then we got our answer
      if(a<answer_count)
      {
        ((struct sockaddr_in*)result)->sin_family = AF_INET;
        ((struct sockaddr_in*)result)->sin_addr = *((struct in_addr *)answer_ptr);
        return 1;
      }
      
    }
    //CNAME record
    else if(htons(rr->type)==RECTYPE_CNAME)
    {
      char ns_string[255];
      int ns_len=from_dns_style(response,answer_ptr,ns_string);
      if(debug)
        printf("The name %s is also known as %s.\n",				
            string_name, ns_string);

    }
    // AAAA record
    else if(htons(rr->type)==RECTYPE_AAAA)	
    {
      if(debug)
      {
        char printbuf[INET6_ADDRSTRLEN];	
        printf("The name %s resolves to IP addr: %s\n",
            string_name,
            inet_ntop(AF_INET6, answer_ptr, printbuf,INET6_ADDRSTRLEN));
      }
      ((struct sockaddr_in6*)result)->sin6_family = AF_INET6;
      ((struct sockaddr_in6*)result)->sin6_addr = *((struct in6_addr *)answer_ptr);
      return 1;
      
    }
    else
    {
      if(debug)
        printf("got unknown record type %hu\n", htons(rr->type));
    }
    answer_ptr+=htons(rr->datalen);
  }
  return 0;
}

// wrapper for inet_ntop that takes a sockaddr_storage as argument
const char * ss_ntop(sss * ss, char * dst, int dstlen)
{		  
  void * addr;
  if (ss->ss_family == AF_INET)
    addr = &(((struct sockaddr_in*)ss)->sin_addr);
  else if (ss->ss_family == AF_INET6)
    addr = &(((struct sockaddr_in6*)ss)->sin6_addr);
  else
  {
    if (debug)
      printf("error parsing ip address\n");
    return NULL;
  }
  return inet_ntop(ss->ss_family, addr, dst, dstlen);
}

/*
 * wrapper for inet_pton that detects a valid ipv4/ipv6 string and returns it in pointer to
 * sockaddr_storage dst
 *
 * return value is consistent with inet_pton
 */
int ss_pton(const char * src, void * dst){
  // try ipv4
  unsigned char buf[sizeof(struct in6_addr)];
  int r;
  r = inet_pton(AF_INET,src,buf);
  if (r == 1){
    char printbuf[INET6_ADDRSTRLEN];
    struct sockaddr_in6 * out = (struct sockaddr_in6*)dst;
    // for socket purposes, we need a v4-mapped ipv6 address
    unsigned char * mapped_dst = (void*)&out->sin6_addr;
    // take the first 4 bytes of buf and put them in the last 4
    // of the return value
    memcpy(mapped_dst+12,buf,4);
    // set the first 10 bytes to 0
    memset(mapped_dst,0,10);
    // set the next 2 bytes to 0xff
    memset(mapped_dst+10,0xff,2);
    out->sin6_family = AF_INET6;
    return 1;
  }
  r = inet_pton(AF_INET6,src,buf);
  if (r == 1){
    struct sockaddr_in6 * out = (struct sockaddr_in6*)dst;
    out->sin6_family = AF_INET6;
    out->sin6_addr = *((struct in6_addr*)buf);
    return 1;
  }
  return r;
}


void read_server_file() {
  root_server_count=0;
  char addr[25];

  FILE *f = fopen("root-servers.txt","r");
  while(fscanf(f," %s ",addr) > 0){
    ss_pton(addr,&root_servers[root_server_count++]);
  }
}



/* constructs a DNS query message for the provided hostname */
int construct_query(uint8_t* query, int max_query, char* hostname,int qtype) {
  memset(query,0,max_query);
  // does the hostname actually look like an IP address? If so, make
  // it a reverse lookup. 
  in_addr_t rev_addr=inet_addr(hostname);
  if(rev_addr!=INADDR_NONE) {
    static char reverse_name[255];		
    sprintf(reverse_name,"%d.%d.%d.%d.in-addr.arpa",
        (rev_addr&0xff000000)>>24,
        (rev_addr&0xff0000)>>16,
        (rev_addr&0xff00)>>8,
        (rev_addr&0xff));
    hostname=reverse_name;
  }
  // first part of the query is a fixed size header
  struct dns_hdr *hdr = (struct dns_hdr*)query;
  // generate a random 16-bit number for session
  uint16_t query_id = (uint16_t) (random() & 0xffff);
  hdr->id = htons(query_id);
  // set header flags to not request recursive query
  hdr->flags = htons(0x0000);	
  // 1 question, no answers or other records
  hdr->q_count=htons(1);
  // add the name
  int query_len = sizeof(struct dns_hdr); 
  int name_len=to_dns_style(hostname,query+query_len);
  query_len += name_len; 
  // now the query type: A/AAAA or PTR. 
  uint16_t *type = (uint16_t*)(query+query_len);
  if(rev_addr!=INADDR_NONE)
  {
    *type = htons(12);
  }
  else
  {
    *type = htons(qtype);
  }
  query_len+=2;
  //finally the class: INET
  uint16_t *class = (uint16_t*)(query+query_len);
  *class = htons(1);
  query_len += 2;
  return query_len;	
}

int resolve_name(int sock, uint8_t * request, int packet_size, uint8_t * response, sss * nameservers, int nameserver_count)
{

  int psize = check_cache(request,response);
  if(psize > 0) return psize;


  //Assume that we're getting no more than 20 NS responses
  char recd_ns_name[20][255];
  sss recd_ns_ips[20];
  int recd_ns_count = 0;
  int recd_ip_count = 0; // additional records
  int response_size = 0;
  // if an entry in recd_ns_ips is 0.0.0.0, we treat it as unassigned
  memset(recd_ns_ips,0,sizeof(recd_ns_ips));
  memset(recd_ns_name,0,20*255);
  int retries = 5;
  
  if(debug)
    printf("resolve name called with packet size %d\n",packet_size);

  int chosen = random()%nameserver_count;
  sss *chosen_ns = &nameservers[chosen];

  if(debug)
  {
    printf("\nAsking for record using server %d out of %d\n",chosen+1, nameserver_count);
  }

  /* using sockaddr to actually send a packet, so make sure the 
   * port is set
   */
  if(debug)
    printf("ss family: %d\n",chosen_ns->ss_family);

  if(chosen_ns->ss_family == AF_INET)
    ((struct sockaddr_in *)chosen_ns)->sin_port = htons(53);
  else if(chosen_ns->ss_family==AF_INET6)
    ((struct sockaddr_in6 *)chosen_ns)->sin6_port = htons(53);
  else
  {
    // this can happen during recursion if a NS w/o a glue record
    // doesn't resolve properly
    if (debug)
      printf("ss_family not set\n");
  }
  int send_count = sendto(sock, request, packet_size, 0, 
      (struct sockaddr *)chosen_ns, sizeof(struct sockaddr_in6));

  if(send_count<0){
    perror("Send failed");
    exit(1);
  }

  // await the response - not calling recvfrom, don't care who is responding
  response_size = recv(sock, response, UDP_RECV_SIZE, 0);
  if(response_size <= 0) {
		printf("In resolve_name, recv failed\n");
		return -1;
	}

  // discard anything that comes in as a query instead of a response
  if ((response_size > 0) && ((ntohs(((struct dns_hdr *)response)->flags) & 0x8000) == 0))
  {
    if(debug){
      printf("flags: 0x%x\n",ntohs(((struct dns_hdr *)response)->flags) & 0x8000);
      printf("received a query while expecting a response\n");
    }
  }
  if(debug) printf("response size: %d\n",response_size);

  // parse the response to get our answer
  struct dns_hdr * header = (struct dns_hdr *) response;
  uint8_t * answer_ptr = response + sizeof(struct dns_hdr);

  // now answer_ptr points at the first question.
  int question_count = ntohs(header->q_count);
  int answer_count = ntohs(header->a_count);
  int auth_count = ntohs(header->auth_count);
  int other_count = ntohs(header->other_count);

  // skip questions
  for(int q=0; q<question_count; q++){
    char string_name[255];
    memset(string_name,0,255);
    int size=from_dns_style(response, answer_ptr,string_name);
    answer_ptr+=size;
    answer_ptr+=4; //jump over 2 bytes type and 2 bytes class
  }

  if(debug)
    printf("Got %d+%d+%d=%d resource records total.\n",answer_count,auth_count,other_count,answer_count+auth_count+other_count);
  if(answer_count+auth_count+other_count>50){
    printf("ERROR: got a corrupt packet\n");
    return -1;
  }

  /*
   * iterate through answer, authoritative, and additional records
   */
  for(int a=0; a<answer_count+auth_count+other_count;a++)
  {
    // first the name this answer is referring to
    char string_name[255];
    int dnsnamelen=from_dns_style(response,answer_ptr,string_name);
    answer_ptr += dnsnamelen;

    // then fixed part of the RR record
    struct dns_rr* rr = (struct dns_rr*)answer_ptr;
    answer_ptr+=sizeof(struct dns_rr);

    //A record
    if(htons(rr->type)==RECTYPE_A)
    {
      //An A record in the answer section, add response to cache
	  if(a<answer_count){
		add_cache(string_name, response, response_size, ntohl(rr->ttl));

		if(debug)
			printf("Added cache %s with TTL of %d\n", string_name, ntohl(rr->ttl));
	  }
	  int i;
	  //Only loop if we saw NS records, this means we stored hostnames
	  //of authoritive servers
	  for(i=0;i<recd_ns_count;i++){
		//Check to see name matches a stored hostname, error check
		if(strcmp(string_name, (char *)&recd_ns_name[i]) == 0){
			//store ip address in next available spot
			struct sockaddr_in * addr = (struct sockaddr_in *)&recd_ns_ips[recd_ip_count];
			addr->sin_family = AF_INET;
			addr->sin_addr = *((struct in_addr *)answer_ptr);

		//	char *ip = inet_ntoa(*((struct in_addr *)answer_ptr));
		//	ss_pton(ip, &recd_ns_ips[recd_ip_count]);
			recd_ip_count++;
		}
	  }
      if(debug)
        printf("The name %s resolves to IP addr: %s\n",
            string_name,
            inet_ntoa(*((struct in_addr *)answer_ptr)));
    }
    //NS record
    else if(htons(rr->type)==RECTYPE_NS) 
    {
	  //add hostname to recd_ns_name, to be used later when looking at A records
	  //in additional section
	  from_dns_style(response,answer_ptr,(char *)&recd_ns_name[recd_ns_count]);

      if(debug)
        printf("The name %s can be resolved by NS: %s\n",
            string_name, recd_ns_name[recd_ns_count]);
      recd_ns_count++;
    }
    //CNAME record
    else if(htons(rr->type)==RECTYPE_CNAME)
    {
	  //CNAME
      char ns_string[255];
      int ns_len=from_dns_style(response,answer_ptr,ns_string);

      if(debug)
        printf("CNAME: The name %s is also known as %s.\n",				
            string_name, ns_string);


	  //Temp buffers
      uint8_t new_request[UDP_RECV_SIZE];      
	  uint8_t new_response[UDP_RECV_SIZE];

      //build the new request in temp buffer
	  int new_packet_size = construct_query(new_request,UDP_RECV_SIZE,ns_string,RECTYPE_A);

	  //Resolve the new name request, store it in temp buffer
	  new_packet_size = resolve_name(sock, new_request, new_packet_size, new_response, root_servers, root_server_count);
	
		if(new_packet_size < 0) {
			perror("Error trying to resolve cname");
			continue;
		}

		//original request, store the orignial request hostname
		char req_name_buf[255];
		struct dns_hdr *req_hdr = (struct dns_hdr *)request; //needed to copy ID
		uint8_t *req_name = request + sizeof(struct dns_hdr); 
		from_dns_style(request,req_name,req_name_buf);

		//Parse the new response into three sections: header, question hostname, and the rest
		//We can copy everything, but we have to replace the response question hostname
		char new_resp_name_buf[255];//Temp, won't be used, just want size
		struct dns_hdr *new_resp_hdr = (struct dns_hdr*)new_response;

		uint8_t *new_resp_name = new_response + sizeof(struct dns_hdr);
		//get the size
		int new_resp_name_len = from_dns_style(new_response,new_resp_name,new_resp_name_buf);

		//A pointer to the beginning of everything else we want and
		//size of the rest of the new response packet after the question host name
		uint8_t *new_resp_rest = new_resp_name + new_resp_name_len;
		int rest_len = new_packet_size - sizeof(struct dns_hdr) - new_resp_name_len;

		//Overwrite original reponse with new response minus the question hostname
		*header = *new_resp_hdr;
	    header->id = req_hdr->id; //copy original request id

		uint8_t *resp_name = response + sizeof(struct dns_hdr);
		int req_name_len = to_dns_style(req_name_buf,resp_name); //place original request hostname
		uint8_t *resp_rest = resp_name + req_name_len;

		memcpy(resp_rest,new_resp_rest,rest_len);

		response_size = sizeof(struct dns_hdr) + req_name_len + rest_len;
 
		if(answer_count > 0 && a < answer_count) break; //CNAME is an answer
    }
    // SOA record
    else if(htons(rr->type)==RECTYPE_SOA)
    {
      if(debug)	
        printf("Ignoring SOA record\n");
    }
    // AAAA record
    else if(htons(rr->type)==RECTYPE_AAAA)	
    {
	  char printbuf[INET6_ADDRSTRLEN];	
	  int i;
	  for(i=0;i<recd_ns_count;i++){
		//Only after NS record, and stored hostname
		if(strcmp(string_name, (char *)&recd_ns_name[i]) == 0){

			struct sockaddr_in6 * addr = (struct sockaddr_in6 *)&recd_ns_ips[recd_ip_count];
			addr->sin6_family = AF_INET6;
			addr->sin6_addr = *((struct in6_addr *)answer_ptr);

			//inet_ntop(AF_INET6,answer_ptr,printbuf,INET6_ADDRSTRLEN);//convert IPv6 network
			//ss_pton(printbuf, &recd_ns_ips[recd_ip_count]);
			recd_ip_count++;
		}
	  }

      if(debug)
      {
        printf("The name %s resolves to IP addr: %s\n",
            string_name,
            inet_ntop(AF_INET6, answer_ptr, printbuf,INET6_ADDRSTRLEN));
      }
    }
    else
    {
      if(debug)
        printf("got unknown record type %hu\n", htons(rr->type));
    }
    answer_ptr+=htons(rr->datalen);
  }

  if(answer_count == 0){
		if(recd_ip_count >0) //We have more name servers to contact
			return resolve_name(sock,request,packet_size,response,recd_ns_ips,recd_ip_count);
		else if(recd_ns_count > 0){ //Unglued record
			int c=0;
			int new_packet_size=0;
			do{
			uint8_t new_request[UDP_RECV_SIZE];      
			uint8_t new_response[UDP_RECV_SIZE];



			do{
				if(debug) printf("Trying to resolve nonglue record\n");
				//build the new request in temp buffer
				new_packet_size = construct_query(new_request,UDP_RECV_SIZE,recd_ns_name[c],RECTYPE_A);
				//Resolve the new name request, store it in temp buffer
				new_packet_size = resolve_name(sock, new_request, new_packet_size, new_response, root_servers, root_server_count);

				c++;
				if(new_packet_size < 0)
					perror("Error trying to resolve unglued nameserver");

			} while(new_packet_size<=0 && c < recd_ns_count); 
		
			//Tried resolving all non-glued name servers, none succeeded
			if(new_packet_size <= 0 && c>=recd_ns_count) return response_size;

			if(debug) printf("Resolved a nonglue record, now continuing recursive search\n");
			sss ns;
			int ea_ret = extract_answer(new_response,&ns);
			
			if(ea_ret <= 0){
				printf("Error trying to extract answer\n");
				exit(1);
			}
			
			new_packet_size = resolve_name(sock,request,packet_size,response,&ns,1);
			} while(new_packet_size<=0 && c <recd_ns_count);

			if(new_packet_size <= 0 && c>=recd_ns_count) return response_size;

			return new_packet_size;
		}
		else{
		;	
		}//Error no answers and no NS given

  }

  return response_size;

}

int main(int argc, char ** argv){
  int port_num=53;
  int sockfd;
  struct sockaddr_in6 server_address;
  struct dns_hdr * header=NULL;
  char * question_domain=NULL;
  char client_ip[INET6_ADDRSTRLEN];
  char *optString = "dp";
  struct timeval timeout;
  
  int opt = getopt(argc, argv, optString);

  while( opt != -1){
    switch(opt) {
      case 'd':
        debug = 1;
        printf("Debug mode\n");
        break;
      case 'p':
        port_num=atoi(argv[optind]);
        break;
      case '?':
        usage();
        break;
    }
    opt = getopt(argc, argv, optString);
  }

  read_server_file();

  //Create socket as DNS Server
  printf("Creating socket on port: %d\n", port_num);
  sockfd=socket(AF_INET6, SOCK_DGRAM, 0);
  if(sockfd<0){
    perror("Unable to screate socket");
    return -1;
  }
  timeout.tv_sec = 3;
  timeout.tv_usec = 0;
  setsockopt(sockfd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));


  memset(&server_address, 0, sizeof(server_address));
  server_address.sin6_family=AF_INET6;
  server_address.sin6_addr = in6addr_any;
  server_address.sin6_port=htons(port_num);
  if(bind(sockfd, (struct sockaddr *)&server_address, sizeof(server_address))<0){
    perror("Uable to bind");
    return -1;
  }
  if (debug)
    printf("Bind successful\n");
  
  socklen_t addrlen = sizeof(struct sockaddr_in6);
  struct sockaddr_in6 client_address;
  uint8_t request[UDP_RECV_SIZE];
  uint8_t response[UDP_RECV_SIZE];
  int packet_size;
  if(debug)
    printf("Waiting for query...\n");

  while(1){
    if((packet_size = recvfrom(sockfd, request, UDP_RECV_SIZE, 0, (struct sockaddr *)&client_address, &addrlen))<0){
      perror("recvfrom error");
      printf("timed out... %d\n",packet_size);
      continue;
    }
    if(debug)
      printf("received request of size %d\n",packet_size);


    if(packet_size<(int)(sizeof(struct dns_hdr)+sizeof(struct dns_query_section))){
      perror("Receive invalid DNS request");
      continue;
    }

    header = (struct dns_hdr *)response;
    

	struct dns_hdr *req_hdr = (struct dns_hdr*)request;

	req_hdr->flags = req_hdr->flags & htons(0xFEFF); //turn off RD

    packet_size = resolve_name(sockfd, request, packet_size, response, root_servers, root_server_count);
    if (packet_size <= 0)
    {
      perror("failed to receive any answer (unexpected!)");
      continue;
    }
    if(debug)
      printf("outgoing packet size: %d\n",packet_size);

	header->flags = header->flags | htons(0x0080);
    //send the response to client
    int sent_count = sendto(sockfd, response, packet_size, 0, (struct sockaddr*)&client_address, addrlen);
    if(debug)
      printf("Waiting for query...\n");

  }

  return 0;
}


