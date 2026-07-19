.POSIX:
CC      = gcc
CFLAGS  = -std=c11 -Wall -Wextra -Wpedantic -Werror -pthread
LDFLAGS = -lpthread -lrt

TARGETS = sandbox test_binaries/loop test_binaries/spray test_binaries/weasel test_binaries/benign test_binaries/cpu_hog test_binaries/memory_leak

.PHONY: all clean test

all: $(TARGETS)

sandbox: sandbox.c sandbox.h
	$(CC) $(CFLAGS) -o $@ sandbox.c $(LDFLAGS)

test_binaries/loop: test_binaries/loop.c
	$(CC) $(CFLAGS) -o $@ test_binaries/loop.c

test_binaries/spray: test_binaries/spray.c
	$(CC) $(CFLAGS) -o $@ test_binaries/spray.c

test_binaries/weasel: test_binaries/weasel.c
	$(CC) $(CFLAGS) -o $@ test_binaries/weasel.c

test_binaries/benign: test_binaries/benign.c
	$(CC) $(CFLAGS) -o $@ test_binaries/benign.c

test_binaries/cpu_hog: test_binaries/cpu_hog.c
	$(CC) $(CFLAGS) -o $@ test_binaries/cpu_hog.c

test_binaries/memory_leak: test_binaries/memory_leak.c
	$(CC) $(CFLAGS) -o $@ test_binaries/memory_leak.c

test: all
	chmod +x tests/run_tests.sh
	./tests/run_tests.sh

clean:
	rm -f $(TARGETS) sandbox.log
	rm -rf test_runs
