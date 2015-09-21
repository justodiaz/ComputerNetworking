#include <iostream>
#include <unistd.h>
#include <sys/socket.h>

using namespace std;

void i_error(string msg);
ssize_t Send(int sockfd, const void*buf, size_t len, int flags);
ssize_t Recv(int sockfd, void *buf, size_t len, int flags);
void Listen(int s, int backlog);
int Accept(int s, struct sockaddr *addr, socklen_t *addrlen);
int Select(int  n, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
int Shutdown(int sockfd, int how);
void Close(int fd);
