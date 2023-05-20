#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ipc.h"

int main(void)
{
	int fd;
	int ret;
	char buf[BUFSIZE];

    while(1) {
        memset(buf, 0, BUFSIZE);
        scanf("%s", buf);

        if (strcmp(buf, "exit") == 0 || strcmp(buf, "quit") == 0) {
            break;
        }

        fd = create_socket();
        if (fd == -1) {
            perror("unix socket");
            exit(-1);
        }

        ret = connect_socket(fd);

        if (ret == -1) {
            perror("connect unix socket");
            exit(-1);
        }

        send_socket(fd, buf, strlen(buf));

        memset(buf, 0, BUFSIZE);

        recv_socket(fd, buf, BUFSIZE);
        buf[BUFSIZE - 1] = 0;

        printf("Output file: %s\n", buf);

        close_socket(fd);
    }

	return 0;
}
