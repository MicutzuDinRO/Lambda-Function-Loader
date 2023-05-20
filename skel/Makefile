CC=gcc
CFLAGS=-fPIC -Wall -Wextra -g
LDFLAGS=-ldl
OUTPUT_DIR=$(abspath ../checker/output/)
CFLAGS+=-DOUTPUT_TEMPLATE="\"$(OUTPUT_DIR)/out-XXXXXX\""
LDLIBS=./libipc.so

build: outdir server

outdir:
	@mkdir -p $(OUTPUT_DIR)

server: server.o log.o libipc.so
	$(CC) -o $@ $^ $(LDLIBS) $(LDFLAGS)

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
	rm -rf server *.o libipc.so
