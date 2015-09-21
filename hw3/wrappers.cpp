#include "wrappers.h"

void i_error(string msg){
	cerr << msg << std::endl;
	exit(1);
}

ssize_t Send(int sockfd, const void*buf, size_t len, int flags){
	int sent = send(sockfd,buf,len,flags);
	if(sent < 0){
		perror("Send error");
		exit(1);
	}

	if(sent != (int)len)
		i_error("Send() didn't send all bytes...exiting");

	return sent;
}

ssize_t Recv(int sockfd, void *buf, size_t len, int flags){
	int rc = recv(sockfd,buf,len,flags);

	if(rc < 0){ 
		perror("Receive error"); 
		exit(1); 
	}

	return rc;
}

int Getaddrinfo(const char *node, const char *service, 
				const struct addrinfo *hints, struct addrinfo **res){
	int rc = getaddrinfo(node,service,hints,res);

	if(rc){
		if(rc == EAI_SYSTEM){
			perror("getaddrinfo error");
			exit(1);
		}

		i_error(string("getaddrinfo error: ") + gai_strerror(rc));
	}

	return rc;
}
int Socket(int domain, int type, int protocol) 
{
    int rc;

    if ((rc = socket(domain, type, protocol)) < 0){
		perror("Socket failed"); 
		exit(1); 
	}
    return rc;
}

void Bind(int sockfd, struct sockaddr *my_addr, int addrlen) 
{
    int rc;

    if ((rc = bind(sockfd, my_addr, addrlen)) < 0){
		perror("Bind error"); 
		exit(1); 
	}
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

int Select(int  n, fd_set *readfds, fd_set *writefds,
	   fd_set *exceptfds, struct timeval *timeout) 
{
    int rc;

    if ((rc = select(n, readfds, writefds, exceptfds, timeout)) < 0){
		perror("Select error");
		exit(1);
	}

    return rc;
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

void Close(int fd){
	int rc = close(fd);
	
	if(rc < 0){
		perror("Close error");
		exit(1);
	}
}
