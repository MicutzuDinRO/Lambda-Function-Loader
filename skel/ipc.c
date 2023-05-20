#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>

#include "ipc.h"

#define DIE(assertion, call_description)				\
	do {								\
		if (assertion) {					\
			fprintf(stderr, "(%s, %d): ",			\
					__FILE__, __LINE__);		\
			perror(call_description);			\
			exit(errno);					\
		}							\
	} while (0)

static const char socket_path[] = "/tmp/hack.socket";

int create_socket()
{
	int sockfd;
	
	sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	DIE(sockfd < 0, "socket");

	return sockfd;
}

int connect_socket(int fd)
{
	int rc, connectfd;
	struct sockaddr_un addr, raddr;
	socklen_t raddrlen;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, strlen(socket_path)+1, "%s", socket_path);
	rc = bind(fd, (struct sockaddr *) &addr, sizeof(addr));
	DIE(rc < 0, "bind");

	listen(fd, 50);
	DIE(rc < 0, "listen");

	connectfd = accept(fd, (struct sockaddr *) &raddr, &raddrlen);
	DIE(connectfd < 0, "accept");

	return connectfd;
}

ssize_t send_socket(int fd, const char *buf, size_t len)
{
	int rc;

	rc = write(fd, buf, len);
	DIE(rc < 0, "write");

	return 0;
}

ssize_t recv_socket(int fd, char *buf, size_t len)
{
	int rc;

	rc = read(fd, buf, len);
	DIE(rc < 0, "read");

	return 0;
}

void close_socket(int fd)
{
	close(fd);
}

