/* 

   Minimal TCP client example. The client connects to port 8080 on the 
   local machine and prints up to 255 received characters to the console, 
   then exits. To test it, try running a minimal server like this on your
   local machine:

   echo "Here is a message" | nc -l -6 8080

*/

#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

int main(int argc, char** argv) 
{	
  /* inpsired heavily by man 3 getaddrinfo 
  */
  
  if(argc < 2){
	fprintf(stderr, "Usage: %s <URL>\n", argv[0]);
	exit(0);
  }

  struct addrinfo hints;
  struct addrinfo *result, *rp;
  int sock_fd, s;

  memset(&hints,0,sizeof(struct addrinfo));
  hints.ai_family = AF_INET6;
  hints.ai_socktype = SOCK_STREAM;

  //Parse the URI
  //Get host
  char *host = strstr(argv[1], "://");

  if(host == NULL) host = argv[1];
  else host+=3;

  //Get path
  char *path = strchr(host, '/');
  char *defpath = "/index.html";

  if(path == NULL || *(path+1) == '\0' || isspace((int)*(path+1))) path = defpath;


  //Get file
  char *remote_file = path+1;

  char *next;
  while((next = strchr(remote_file,'/')) != NULL){
	remote_file = next+1;
	next = remote_file;
  }

  if(*remote_file == '\0' || isspace((int)*remote_file)) remote_file = defpath+1;

 //Setup Connection
  s = getaddrinfo(host,"80",&hints,&result);
  if (0 != s){
    perror("error populating address structure");
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
  char msg[255];
  memset(&msg,0,sizeof(msg));

  sprintf(msg, "GET %s HTTP/1.0\r\n\r\n", path);

  int msg_len = strlen(msg);
  if(send(sock_fd, msg, msg_len, 0) != msg_len) { perror("Send failed"); exit(1); }


 //Respone
  char data[1000000];
  memset(&data,0,sizeof(data));

  int curr_recv = recv(sock_fd, data, sizeof(data), 0);

  if(curr_recv==0) { fprintf(stderr, "Did not receive any data from host\n"); exit(1); }

  //Requires multiple recv calls to get entire file.
  int recv_count = 0;
  while(curr_recv > 0){
	recv_count += curr_recv;
	curr_recv = recv(sock_fd, data+recv_count, sizeof(data)-recv_count,0);
  }

  if(curr_recv<0) { perror("Receive failed");	exit(1); }


 //Parse received response
 //What if "200 OK" in body of message? False OK. Parse correctly.
  char *recv_status = strstr(data,"200 OK");
 
  if(recv_status == NULL) {
	fprintf(stderr, "Could not obtain webpage, exiting...\n");
	exit(1);
  }

  char *entity_body = strstr(data,"\r\n\r\n") + 4;

  //Count number of bytes in header
  int head_bytes = 0;

  char *tmp = data;
  while(tmp != entity_body){
	head_bytes++;
        tmp++;
  }

  int data_bytes = recv_count - head_bytes;

  //Create file on fs, write received bytes to that file
  int saved_fd = open(remote_file, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if(saved_fd<0) {perror("Open failed"); exit(1);}

  if(write(saved_fd,entity_body,data_bytes) != data_bytes) {perror("Write failed"); exit(1);}

  close(saved_fd);

  shutdown(sock_fd,SHUT_RDWR);
  return 0;
}
