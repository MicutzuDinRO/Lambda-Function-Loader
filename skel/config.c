#include "config.h"
#include "log.h"
#include <stdlib.h>

void parse_config_file(char *configname, int *network, int *log_level)
{
	char buf[200];
	char *rc = NULL;
	char *name, *value;
	FILE *configfile = fopen(configname, "r");

	if (configfile == NULL) {
		fprintf(stderr, "Could not parse config file");
		exit(EXIT_FAILURE);
	}

	rc = fgets(buf, 200, configfile);

	while (rc != NULL) {
		name = strtok(buf, "= \n");
		value = strtok(NULL, "= \n");
		printf("%s %s\n", name, value);

		if (!strcmp(name, "log_level") ||
				!strcmp(name, "loglevel") ||
				!strcmp(name, "log") ||
				!strcmp(name, "log-level")) {
			if (!strcmp(value, "debug")) {
				*log_level = LOG_DEBUG;
			} else if (!strcmp(value, "info")) {
				*log_level = LOG_INFO;
			} else if (!strcmp(value, "warning")) {
				*log_level = LOG_WARNING;
			} else if (!strcmp(value, "error")) {
				*log_level = LOG_ERROR;
			} else {
				fprintf(stderr,
				"Log level must be one of debug, info, warning or error.\n");

				exit (EXIT_FAILURE);
			}
		} else if (!strcmp(name, "network") || !strcmp(name, "net-sockets")) {
			if (!strcmp(value, "yes") || !strcmp(value, "true")) {
				*network = 1;
			}
		}

		rc = fgets(buf, 200, configfile);
	}
}
