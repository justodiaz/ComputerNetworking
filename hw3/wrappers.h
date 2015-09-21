#include <iostream>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>

using namespace std;

void i_error(string msg);
ssize_t Send(int sockfd, const void*buf, size_t len, int flags);
ssize_t Recv(int sockfd, void *buf, size_t len, int flags);
int Getaddrinfo(const char *node, const char *service, 
				const struct addrinfo *hints, struct addrinfo **res);
int Socket(int domain, int type, int protocol);
void Bind(int sockfd, struct sockaddr *my_addr, int addrlen);
void Listen(int s, int backlog);
int Accept(int s, struct sockaddr *addr, socklen_t *addrlen);
int Select(int  n, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
int Shutdown(int sockfd, int how);
void Close(int fd);
