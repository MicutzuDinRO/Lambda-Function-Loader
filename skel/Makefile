CC=gcc
CFLAGS=-fPIC -Wall -Wextra -g
LDFLAGS=-ldl
OUTPUT_DIR=$(abspath ../checker/output/)
CFLAGS+=-DOUTPUT_TEMPLATE="\"$(OUTPUT_DIR)/out-XXXXXX\""
LDLIBS=./libipc.so

build: outdir server client_multi client_net

outdir:
	@mkdir -p $(OUTPUT_DIR)

server: server.o log.o libipc.so
	$(CC) -o $@ $^ $(LDLIBS) $(LDFLAGS)

client_%: client_%.o $(LDLIBS)

client_%.o: client_%.c
	$(CC) $(CFLAGS) -o $@ -c $<

server.o: server.c server.h ipc.h
	$(CC) $(CFLAGS) -o $@ -c $<

libipc.so: ipc.o
	$(CC) -shared -o $@ $^

ipc.o: ipc.c ipc.h
	$(CC) $(CFLAGS) -o $@ -c $<

log.o: log.c log.h
	$(CC) $(CFLAGS) -o $@ -c $<

.PHONY: clean
clean:
	rm -rf server client_net client_multi *.o libipc.so $(OUTPUT_DIR)
