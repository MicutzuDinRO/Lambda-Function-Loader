#include "log.h"

static int log_fd;
static int log_level;

void write_log(char *message, int log_t)
{
	if (log_t < log_level)
		return;

	switch (log_t) {
	case LOG_INFO:
		write(log_fd, "INFO: ", 6);
		break;
	case LOG_DEBUG:
		write(log_fd, "DEBUG: ", 7);
		break;
	case LOG_WARNING:
		write(log_fd, "WARNING: ", 9);
		break;
	case LOG_ERROR:
		write(log_fd, "ERROR: ", 7);
		break;
	}

	write(log_fd, message, strlen(message));
}

int init_log(int level, char *filename)
{
	log_level = level;

	log_fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0666);
}
