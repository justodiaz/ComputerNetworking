/* 

   Minimal TCP client example. The client connects to port 8080 on the 
   local machine and prints up to 255 received characters to the console, 
   then exits. To test it, try running a minimal server like this on your
   local machine:

   echo "Here is a message" | nc -l -6 8080

*/


#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <stdio.h>

int main(int argc, char** argv) 
{	
  /* inpsired heavily by man 3 getaddrinfo 
  */

  struct addrinfo hints;
  struct addrinfo * result, * rp;
  int sock_fd, s;

  hints.ai_socktype = SOCK_STREAM;
  memset(&hints,0,sizeof(struct addrinfo));

  s = getaddrinfo("::1","8080",&hints,&result);
  if (0 != s){
    perror("error populating address structure");
    exit(1);
  }
  for (rp = result; rp != NULL; rp = rp->ai_next) {
    sock_fd = socket(rp->ai_family, rp->ai_socktype,
        rp->ai_protocol);
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

  char buf[255];
  memset(&buf,0,sizeof(buf));
  int recv_count = recv(sock_fd, buf, 255, 0);
  if(recv_count<0) { perror("Receive failed");	exit(1); }

  printf("%s",buf);																							

  shutdown(sock_fd,SHUT_RDWR);
}
