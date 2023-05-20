#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ipc.h"

int main(int argc, char *argv[])
{
	int fd;
	int ret;
	char buf[BUFSIZE];

	memset(buf, 0, BUFSIZE);

	switch(argc)
	{
	    case 2:
		snprintf(buf, BUFSIZE, "%s", argv[1]);
		break;
	    case 3:
		snprintf(buf, BUFSIZE, "%s %s", argv[1], argv[2]);
		break;
	    case 4:
		snprintf(buf, BUFSIZE, "%s %s %s", argv[1], argv[2], argv[3]);
		break;
	    default:
		fprintf(stderr, "Illegal client format\n");
		exit(-1);
	}

	fd = create_net_socket();
	if (fd == -1) {
		perror("network socket");
		exit(-1);
	}

	ret = connect_net_socket(fd);

	if (ret == -1) {
		perror("connect network socket");
		exit(-1);
	}

	send_socket(fd, buf, strlen(buf));

	memset(buf, 0, BUFSIZE);

	recv_socket(fd, buf, BUFSIZE);
	buf[BUFSIZE - 1] = 0;

	printf("Output file: %s\n", buf);

	close_socket(fd);

	return 0;
}
