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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/resource.h>

#include "ipc.h"
#include "server.h"
#include "log.h"
#include "config.h"

#ifndef OUTPUTFILE_TEMPLATE
#define OUTPUTFILE_TEMPLATE "../checker/output/out-XXXXXX"
#endif

#ifndef LOG_FILE
#define LOG_FILE "server.log"
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

static const int PORT = 12345;

static const char socket_path[] = "/tmp/server_socket";

static int end_loop;

static void usage(char **argv)
{
	dup2(STDERR_FILENO, STDOUT_FILENO);

	printf("Usage: %s [OPTIONS]\n", argv[0]);
	printf("Where the options are described below:\n");
	printf("\n\t--log-level=<debug|info|warning|error>: sets the log level");
	printf("\n\t--network | --net | --n: use network sockets instead of unix sockets");
	printf("\n\t--show-stats: show server realtime stats");
	printf("\n\t--config FILENAME: use the config file FILENAME");
	printf("\n\nThe config file can have the following options:");
	printf("\n\t<log_level | log | log-level>=<debug | info | warning | error>");
	printf("\n\tshow-stats=<yes | true>");
	printf("\n\t<network | net-sockets>=<yes | true>\n\n");
}

static void sigint_handler(int sig)
{
	end_loop = 1;
}

static void sigchld_handler(int sig)
{
	pid_t pid;
	int status;

	while((pid = waitpid(-1, &status, WNOHANG)) > 0)
		;
}

static void sigsegv_handler(int sig)
{
	write_log("Failed to execute, got SIGSEGV\n", LOG_WARNING);

	exit(EXIT_FAILURE);
}

static void print_stats()
{
	struct rusage usage;

	getrusage(RUSAGE_CHILDREN, &usage);

	fprintf(stderr, "Server page faults: %ld\n",
			usage.ru_minflt + usage.ru_majflt);

	fprintf(stderr, "Server voluntary ctx switches: %ld\n",
			usage.ru_nvcsw);

	fprintf(stderr, "Server involuntary ctx switches: %ld\n",
			usage.ru_nivcsw);
}

static int lib_prehooks(struct lib *lib)
{
	int fd;
	int rc;

	struct sigaction segv_action;
	memset(&segv_action, 0, sizeof(struct sigaction));
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
	char log[200];

	sprintf(log, "Opening library: %s\n", lib->libname);
	write_log(log, LOG_DEBUG);

	rc = dlopen(lib->libname, RTLD_LAZY);

	char *err = dlerror();

	if (err != NULL) {
		printf("Error: %s %s ", lib->libname,
				lib->funcname != NULL ? lib->funcname : "run");

		if (lib->filename != NULL)
			printf("%s ", lib->filename);

		printf("could not be executed.\n");

		sprintf(log, "Failed to open: %s\n", err);
		write_log(log, LOG_WARNING);

		return -1;
	}

	lib->handle = rc;

	return 0;
}

static int lib_execute(struct lib *lib)
{
	void *func;
	char log[200];

	sprintf(log, "Executing function: %s\n",
			lib->funcname != NULL ? lib->funcname : "run");
	write_log(log, LOG_INFO);

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

		sprintf(log, "Failed to execute: %s\n", err);
		write_log(log, LOG_WARNING);

		return -1;
	}

	if (lib->filename != NULL) {
		((void (*)(void *))func)(lib->filename);
	} else {
		((void (*)(void))func)();
	}

	return 0;
}

static int lib_close(struct lib *lib)
{
	char log[200];

	sprintf(log, "Closing library: %s\n", lib->libname);
	write_log(log, LOG_DEBUG);

	return dlclose(lib->handle);
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

	return 0;
}

static int parse_command(const char *buf, char *name, char *func, char *params)
{
	return sscanf(buf, "%s %s %s", name, func, params);
}

int main(int argc, char **argv)
{
	struct lib lib;

	int listenfd, connectfd;
	struct sockaddr_un addrun, raddrun;
	struct sockaddr_in addrin, raddrin;
	socklen_t raddrunlen = sizeof(struct sockaddr_un), raddrinlen = sizeof(struct sockaddr_in);
	char buffer[BUFSIZ];
	char config_file[200];
	int rc, netsock = -1, show_stats = 0;
	int log_level = LOG_WARNING;

	memset(buffer, 0, BUFSIZ);

	for (int i = 1; i < argc; i ++) {
		if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
			usage(argv);
			exit(EXIT_SUCCESS);
		} else if (!strncmp(argv[i], "--log-level", 12)) {
			// log level was set through a config file
			if (log_level != LOG_WARNING)
				continue;

			i++;

			if (!strcmp(argv[i], "debug"))
				log_level = LOG_DEBUG;
			if (!strcmp(argv[i], "info"))
				log_level = LOG_INFO;
			if (!strcmp(argv[i], "warning"))
				log_level = LOG_WARNING;
			if (!strcmp(argv[i], "error"))
				log_level = LOG_ERROR;
		} else if ((strcmp(argv[i], "--network") == 0 ||
				strcmp(argv[i], "--net") == 0 ||
				strcmp(argv[i], "--n") == 0) &&
				netsock == -1) {
			netsock = 1;
		} else if (!strncmp(argv[i], "--config", 8)) {
			i++;

			if (strlen(argv[i]) > 200) {
				fprintf(stderr, "Config file path too big, max 200 characters\n");
				exit(EXIT_FAILURE);
			}

			strncpy(config_file, argv[i], 200);

			parse_config_file(argv[i], &netsock, &log_level, &show_stats);
		} else if (!strcmp(argv[i], "--show-stats")) {
			show_stats = 1;
		} else {
			usage(argv);
			exit(EXIT_FAILURE);
		}
	}

	if (netsock == -1)
		netsock = 0;

	int log_fd = init_log(log_level, LOG_FILE);

	struct sigaction term_action;
	memset(&term_action, 0, sizeof(struct sigaction));
	term_action.sa_handler = sigint_handler;
	term_action.sa_flags = SA_NODEFER;
	rc = sigaction(SIGINT, &term_action, NULL);

	DIE(rc < 0, "sigaction: ");

	struct sigaction chld_action;
	memset(&chld_action, 0, sizeof(struct sigaction));
	chld_action.sa_handler = sigchld_handler;
	chld_action.sa_flags = SA_NODEFER;
	rc = sigaction(SIGCHLD, &chld_action, NULL);

	DIE(rc < 0, "sigaction: ");

	memset(&raddrin, 0, sizeof(raddrin));
	memset(&addrin, 0, sizeof(addrin));
	memset(&raddrun, 0, sizeof(raddrun));
	memset(&addrun, 0, sizeof(addrun));


	if (netsock == 1) {
		listenfd = create_net_socket();
		addrin.sin_family = AF_INET;
		addrin.sin_addr.s_addr = htonl(INADDR_ANY);
		addrin.sin_port = htons(PORT);
		rc = bind(listenfd, (struct sockaddr *) &addrin, sizeof(addrin));
		DIE(rc < 0, "bind");
	}
	else {
		listenfd = create_socket();
		addrun.sun_family = AF_UNIX;
		snprintf(addrun.sun_path, strlen(socket_path)+1, "%s", socket_path);
		unlink(socket_path);
		rc = bind(listenfd, (struct sockaddr *) &addrun, sizeof(addrun));
		DIE(rc < 0, "bind");
	}


	listen(listenfd, 100);
	DIE(rc < 0, "listen");

	while(end_loop == 0) {
		if (show_stats != 0)
			print_stats();

		connectfd = netsock == 1 ?
		accept(listenfd, (struct sockaddr *) &raddrin, &raddrinlen) :
		accept(listenfd, (struct sockaddr *) &raddrun, &raddrunlen);

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
			char libname[200], functionname[200], filename[200];
			char sendf[200];

			memset(libname, 0, 200);
			memset(functionname, 0, 200);
			memset(filename, 0, 200);
			memset(sendf, 0, 200);
			sprintf(sendf, "%s", OUTPUTFILE_TEMPLATE);

			recv_socket(connectfd, buffer, BUFSIZE);

			parse_command(buffer, libname, functionname, filename);

			mkstemp(sendf);

			pid_t pid2 = fork();

			switch (pid2) {
			case -1:
				DIE(1, "fork: ");
				break;
			case 0:
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

				lib_run(&lib);

				break;
			default:
				waitpid(pid2, NULL, 0);
				send_socket(connectfd, sendf, 50);
			}

			close(connectfd);
			goto out;
			break;
		default:
			/*rc = waitpid(-1, &wstatus, WNOHANG);*/
			close(connectfd);
			break;
		}
	}

	close(connectfd);
	int wpid, status;
	while ((wpid = wait(&status)) > 0);

out:
	close(listenfd);
	close(log_fd);

	return 0;
}
