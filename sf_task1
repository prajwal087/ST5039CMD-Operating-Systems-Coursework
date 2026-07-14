.POSIX:
CC      = gcc
CFLAGS  = -std=c11 -Wall -Wextra -Wpedantic -Werror -D_GNU_SOURCE \
	  -I/tmp/ssl-dev/usr/include -I/tmp/ssl-dev/usr/include/x86_64-linux-gnu \
	  -I/tmp/cap-dev/usr/include
LDFLAGS = -L/tmp/ssl-dev/usr/lib/x86_64-linux-gnu \
	  -Wl,-rpath,/tmp/ssl-dev/usr/lib/x86_64-linux-gnu \
	  -lcrypto -lpthread

TARGETS = backend frontend tests/rogue_client

.PHONY: all clean test test-rogue pwfile

all: $(TARGETS)

backend: backend.c common.h
	$(CC) $(CFLAGS) -o $@ backend.c $(LDFLAGS)

frontend: frontend.c common.h
	$(CC) $(CFLAGS) -o $@ frontend.c $(LDFLAGS)

tests/rogue_client: tests/rogue_client.c common.h
	$(CC) $(CFLAGS) -o $@ tests/rogue_client.c $(LDFLAGS)

pwfile:
	@echo "Creating passwd.store with test credentials..."
	@echo "student:prajwal"   > passwd.store
	@echo "admin:Mrprajwal"  >> passwd.store
	@chmod 600 passwd.store

test-rogue: $(TARGETS) pwfile
	@echo "=== Starting backend (requires root for setresuid) ==="
	@-sudo pkill -9 backend 2>/dev/null
	@echo "[test] launching backend..."
	@sudo ./backend &
	@sleep 1
	@echo "[test] launching rogue client..."
	@./tests/rogue_client; true
	@echo "[test] launching legitimate client..."
	@./frontend student <<< "prajwal"; true
	@sudo pkill -9 backend 2>/dev/null
	@rm -f $(SOCK_PATH) 2>/dev/null

clean:
	rm -f $(TARGETS) passwd.store
	rm -f /tmp/auth_valve.sock
