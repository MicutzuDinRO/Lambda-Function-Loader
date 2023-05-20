#include <dlfcn.h>
#include <fcntl.h>
#include <signal.h>
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

static int end_loop;
static int got_sigsegv;

static struct lib current_lib;

static void sigint_handler(int sig)
{
	end_loop = 1;
}

static void sigchld_handler(int sig)
{
	int status = 0;
	int pid = 0;

	do {
		/*pid = waitpid(-1, &status, WNOHANG);*/
		pid = wait(&status);
	} while (pid >= 0 && (!WIFEXITED(status) && !WIFSIGNALED(status)));
}

static void sigsegv_handler(int sig)
{
	got_sigsegv = 1;
	printf("Error: %s %s ", current_lib.libname,
			current_lib.funcname != NULL ? current_lib.funcname : "run");

	if (current_lib.filename != NULL)
		printf("%s ", current_lib.filename);

	printf("could not be executed.\n");
	exit(EXIT_FAILURE);
}

static int lib_prehooks(struct lib *lib)
{
	int fd;
	int rc;

	struct sigaction segv_action;
	segv_action.sa_handler = sigsegv_handler;
	segv_action.sa_flags = SA_NODEFER;
	rc = sigaction(SIGSEGV, &segv_action, NULL);

	DIE(rc < 0, "sigaction: ");

	fd = open(lib->outputfile, O_WRONLY | O_TRUNC);
	DIE(fd < 0, "open");

	dup2(fd, STDOUT_FILENO);
	close(fd);

	return 0;
}

static int lib_load(struct lib *lib)
{
	void *rc;

	rc = dlopen(lib->libname, RTLD_LAZY);

	char *err = dlerror();

	if (err != NULL) {
		printf("Error: %s %s ", lib->libname,
				lib->funcname != NULL ? lib->funcname : "run");

		if (lib->filename != NULL)
			printf("%s ", lib->filename);

		printf("could not be executed.\n");
		/*printf("%s\n", strerror(errno));*/
		/*printf("%s\n", err);*/

		return -1;
	}

	lib->handle = rc;

	return 0;
}

static int lib_execute(struct lib *lib)
{
	void *func;

	if (lib->funcname != NULL)
		func = dlsym(lib->handle, lib->funcname);
	else
		func = dlsym(lib->handle, "run");

	char *err = dlerror();

	if (err != NULL) {
		printf("Error: %s %s ", lib->libname,
				lib->funcname != NULL ? lib->funcname : "run");

		if (lib->filename != NULL)
			printf("%s ", lib->filename);

		printf("could not be executed.\n");

		return -1;
	}

	if (lib->filename != NULL) {
		((void (*)(void *))func)(lib->filename);
	} else {
		((void (*)(void))func)();
	}

	if (got_sigsegv != 0) {
		printf("Error: %s %s ", lib->libname,
				lib->funcname != NULL ? lib->funcname : "run");

		if (lib->filename != NULL)
			printf("%s ", lib->filename);

		printf("could not be executed.\n");

		fprintf(stderr, "TEST\n");

		return -1;
	}

	return 0;
}

static int lib_close(struct lib *lib)
{
	return dlclose(lib->handle);
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
	struct sigaction term_action;
	term_action.sa_handler = sigint_handler;
	term_action.sa_flags = SA_NODEFER;
	rc = sigaction(SIGINT, &term_action, NULL);

	DIE(rc < 0, "sigaction: ");

	struct sigaction chld_action;
	chld_action.sa_handler = sigchld_handler;
	chld_action.sa_flags = SA_NODEFER;
	/*rc = sigaction(SIGCHLD, &chld_action, NULL);*/
	signal(SIGCHLD, SIG_IGN);

	DIE(rc < 0, "sigaction: ");

	listenfd = create_socket();

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, strlen(socket_path)+1, "%s", socket_path);

	unlink(socket_path);
	rc = bind(listenfd, (struct sockaddr *) &addr, sizeof(addr));
	DIE(rc < 0, "bind");

	listen(listenfd, 100);
	DIE(rc < 0, "listen");

	while(end_loop == 0) {

		connectfd = accept(listenfd, (struct sockaddr *) &raddr, &raddrlen);
		/*DIE(connectfd < 0, "accept");*/
		if (connectfd < 0)
			continue;

		pid_t pid;

		pid = fork();

		switch (pid) {
		case -1:
			DIE(pid < 0, "fork: ");
			break;
		case 0:
			(void)(pid);
			ssize_t recv_size, send_size;
			char libname[200], functionname[200], filename[200];
			char sendf[200];

			memset(libname, 0, 200);
			memset(functionname, 0, 200);
			memset(filename, 0, 200);
			memset(sendf, 0, 200);
			sprintf(sendf, "%s", OUTPUTFILE_TEMPLATE);

			recv_size = recv_socket(connectfd, buffer, BUFSIZE);

			parse_command(buffer, libname, functionname, filename);

			int tmpfd = mkstemp(sendf);

			lib.libname = libname;

			if (strlen(functionname) > 0)
				lib.funcname = functionname;
			else
				lib.funcname = NULL;

			if (strlen(filename) > 0)
				lib.filename = filename;
			else
				lib.filename = NULL;

			lib.outputfile = sendf;

			current_lib = lib;

			ret = lib_run(&lib);

			/*printf("%s\n%s\n%s\n", libname, functionname, filename);*/

			send_size = send_socket(connectfd, sendf, 50);

			/*printf("ACCEPTED\n");*/

			close(connectfd);
			goto out;
			break;
		default:
			rc = waitpid(-1, &wstatus, WNOHANG);
			close(connectfd);
			break;
		}

		/* TODO - get message from client */
		/* TODO - parse message with parse_command and populate lib */
		/* TODO - handle request from client */
	}

	int wpid, status;
	while ((wpid = wait(&status)) > 0);

out:
	close(listenfd);

	return 0;
}
