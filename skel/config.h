#ifndef __CONFIG_PARSE__
#define __CONFIG_PARSE__

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

void parse_config_file(char *configname, int *network, int *log_level);

#endif
