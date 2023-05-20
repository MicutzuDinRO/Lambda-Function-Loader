#ifndef __SERVER_LOG__
#define __SERVER_LOG__

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

enum log_type {
	LOG_DEBUG,
	LOG_INFO,
	LOG_WARNING,
	LOG_ERROR
};

void write_log(char *message, int log_t);
int init_log(int level, char *filename);

#endif
