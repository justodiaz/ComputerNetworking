//Justo Diaz Esquivel
//CS 450 Fall 2015 -- UIC
#include <sys/socket.h>
#include <sys/types.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

//Buffer lenghts
#define MAXPROTOCOL 10
#define MAXHOST 100
#define MAXPATH 100
#define MAXFILE 100
#define MAXREQUEST 255
#define MAXRESPONSE 1000000
#define MAXSTATLINE 100

//Copies a string using pointers, appends null at the end
void copy_str_ptr(const char *from, char *to, const char *end, int limit){
	int c = 0;
	while(from != end && c < limit-1){
		*to = *from;
		to++; from++; c++;
	}

 	*to = '\0';
}

//Custom UIR parser
void uri_parser_buffer(char *uri, char *protocol, int l1, char *host, int l2, char *path, int l3, char *file, int l4){
	char *p1, *p2, *p3, *t_p3, *p4;

	p1 = strstr(uri, "://");

	if(p1 == NULL) {
		snprintf(protocol,l1,"http");
		p1 = uri;
	}
	else {
		copy_str_ptr(uri,protocol,p1,l1);
		p1+=3;
	}

	p2 = strchr(p1, '/');

	if(p2 == NULL){
		snprintf(host,l2,"%s",p1);
		snprintf(path,l3,"/");
		snprintf(file,l4,"index.html");
		return;
	}
	else copy_str_ptr(p1,host,p2,l2);

	t_p3 = p2;

	do{
		p3 = t_p3;
		t_p3 = strchr(t_p3+1,'/');
	} while(t_p3 != NULL);

	p3++;
	
	copy_str_ptr(p2,path,p3,l3);

	p4 = strchr(p3,'\0');
	
	if(p3 == p4)
		snprintf(file,l4,"index.html");
	else
		copy_str_ptr(p3,file,p4,l4);
}

int main(int argc, char** argv) 
{	
  
  if(argc < 2){
	fprintf(stderr, "Usage: %s <URI>\n", argv[0]);
	exit(0);
  }

  char protocol[MAXPROTOCOL];
  char host[MAXHOST];
  char path[MAXPATH];
  char file[MAXFILE];
  
  uri_parser_buffer(argv[1],protocol,MAXPROTOCOL,host,MAXHOST,path,MAXPATH,file,MAXFILE);

 //Setup Connection
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  int sock_fd, s;

  memset(&hints,0,sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC; //AF_INET6 does not work?
  hints.ai_socktype = SOCK_STREAM;//SOCK_STREAM, SOCK_DGRAM
  hints.ai_protocol = 0; //"any"

  s = getaddrinfo(host,protocol,&hints,&result);
  if (0 != s){
    fprintf(stderr,"Error populating address structure: %s\n", gai_strerror(s));
    exit(1);
  }
  for (rp = result; rp != NULL; rp = rp->ai_next) {
    sock_fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sock_fd == -1)
      continue;

    if (connect(sock_fd, rp->ai_addr, rp->ai_addrlen) != -1)
      break; /* Success */

    close(sock_fd);
  }

  if (rp == NULL) {
    fprintf(stderr, "could not connect\n");
    exit(1);
  }

  freeaddrinfo(result);

  //Request
  char request[MAXREQUEST];
  memset(&request,0,MAXREQUEST);

  snprintf(request, MAXREQUEST, "GET %s%s HTTP/1.0\r\n", path, file);
  sprintf(request,"%sHost: %s\r\n\r\n",request,host);

  printf("Sending Request...\n%s",request); 

  int request_len = strlen(request);
  if(send(sock_fd, request, request_len, 0) != request_len) { perror("Send failed"); exit(1); }

 //Respone
  char response[MAXRESPONSE];
  memset(&response,0,MAXRESPONSE);

  int tmp_recv = recv(sock_fd, response, MAXRESPONSE, 0);
  if(tmp_recv==0) { fprintf(stderr, "Error: Didn't receive a response from host\n"); exit(1); }

  //Requires multiple recv calls to get entire file.
  int total_recv = 0;
  int tmp_maxresponse = MAXRESPONSE;

  while(tmp_recv > 0){
	total_recv += tmp_recv;
        tmp_maxresponse = MAXRESPONSE-total_recv;
	tmp_recv = recv(sock_fd, response+total_recv, tmp_maxresponse<0 ? 0:tmp_maxresponse,0);
  }

  if(tmp_recv<0) { perror("Receive failed"); exit(1); }

 //Parse received response
  char status_line[MAXSTATLINE];
  char *resp_body = strstr(response,"\r\n\r\n");

  if(resp_body == NULL) { 
	fprintf(stderr, "Error:Received response doesn't appear to follow HTTP protocol"); 
	exit(1);
  }
  resp_body += 4;

  copy_str_ptr(response, status_line, strstr(response,"\r\n"), MAXSTATLINE);

  printf("Receiving...\n%s\n", status_line);

  //Didn't get 200 OK status, dont' save anything just quit
  if(!strstr(status_line,"200 OK")){
	printf("No file saved.\n");
	shutdown(sock_fd,SHUT_RDWR);
	return 0;
  }
  //Count number of bytes in header
  int head_bytes = 0;

  char *tmp = response;
  while(tmp != resp_body){
	head_bytes++;
        tmp++;
  }

  int body_bytes = total_recv - head_bytes;

  //Create file on fs, write received bytes to that file
  int saved_fd = open(file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if(saved_fd<0) {perror("Open failed"); exit(1);}

  if(write(saved_fd,resp_body,body_bytes) != body_bytes) {perror("Write failed"); exit(1);}

  printf("File \"%s\" saved.\n", file);
  close(saved_fd);
  shutdown(sock_fd,SHUT_RDWR);
  return 0;
}

