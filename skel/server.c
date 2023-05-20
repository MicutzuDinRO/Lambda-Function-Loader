#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <errno.h>
#include <sys/wait.h>

#include "ipc.h"
#include "server.h"

#ifndef OUTPUTFILE_TEMPLATE
#define OUTPUTFILE_TEMPLATE "../checker/output/out-XXXXXX"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define ERR(assertion, call_description)				\
	do {								\
		if (assertion)						\
			fprintf(stderr, "%s: %s",			\
				call_description, strerror(errno));	\
	} while (0)

#define DIE(assertion, call_description)				\
	do {								\
		if (assertion)	{					\
			fprintf(stderr, "%s: %s",			\
				call_description, strerror(errno));	\
			exit(EXIT_FAILURE);				\
		}							\
	} while (0)

#ifdef __cplusplus
}
#endif

static const char socket_path[] = "/tmp/server_socket";

static int lib_prehooks(struct lib *lib)
{
	return 0;
}

static int lib_load(struct lib *lib)
{
	return 0;
}

static int lib_execute(struct lib *lib)
{
	return 0;
}

static int lib_close(struct lib *lib)
{
	return 0;
}

static int lib_posthooks(struct lib *lib)
{
	return 0;
}

static int lib_run(struct lib *lib)
{
	int err;

	err = lib_prehooks(lib);
	if (err)
		return err;

	err = lib_load(lib);
	if (err)
		return err;

	err = lib_execute(lib);
	if (err)
		return err;

	err = lib_close(lib);
	if (err)
		return err;

	return lib_posthooks(lib);
}

static int parse_command(const char *buf, char *name, char *func, char *params)
{
	return sscanf(buf, "%s %s %s", name, func, params);
}

int main(void)
{
	int ret;
	struct lib lib;

	int listenfd, connectfd;
	struct sockaddr_un addr, raddr;
	socklen_t raddrlen;
	char buffer[BUFSIZ];
	int rc;
	int wstatus;

	/* TODO - Implement server connection */

	listenfd = create_socket();

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, strlen(socket_path)+1, "%s", socket_path);

	rc = bind(listenfd, (struct sockaddr *) &addr, sizeof(addr));
	DIE(rc < 0, "bind");

	listen(listenfd, 50);
	DIE(rc < 0, "listen");

	while(1) {

		connectfd = accept(listenfd, (struct sockaddr *) &raddr, &raddrlen);
		DIE(connectfd < 0, "accept");

		pid_t pid;

		pid = fork();

		switch (pid) {
		case -1:
			DIE(pid < 0, "fork: ");
			break;
		case 0:
			(void)(pid);
			ssize_t recv_size, send_size;
			char libname[50], functionname[50], filename[50];
			char sendf[50];

			memset(libname, 0, 50);
			memset(functionname, 0, 50);
			memset(filename, 0, 50);
			memset(sendf, 0, 50);
			sprintf(sendf, "%s", OUTPUTFILE_TEMPLATE);

			recv_size = recv_socket(connectfd, buffer, BUFSIZE);

			parse_command(buffer, libname, functionname, filename);

			int tmpfd = mkstemp(sendf);

			lib.libname = libname;
			lib.funcname = functionname;
			lib.filename = filename;
			/*lib.fd = tmpfd;*/

			ret = lib_run(&lib);

			printf("%s\n%s\n%s\n", libname, functionname, filename);

			send_size = send_socket(connectfd, sendf, 50);

			printf("ACCEPTED\n");

			goto out;
			break;
		default:
			rc = waitpid(pid, &wstatus, 0);
			printf("%d\n", WEXITSTATUS(wstatus));
			break;
		}

		/* TODO - get message from client */
		/* TODO - parse message with parse_command and populate lib */
		/* TODO - handle request from client */
	}

out:

	return 0;
}
