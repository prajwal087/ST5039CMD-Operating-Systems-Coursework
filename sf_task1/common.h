#ifndef COMMON_H
#define COMMON_H

#include <sys/types.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define SOCK_PATH  "/tmp/avs.sock"
#define SHM_PATH   "/auth_cred_store"
#define CHALLENGE_SZ 32
#define HASH_SZ      32
#define USERNAME_MAX 64
#define MAX_RETRIES  3
#define AUTH_TIMEOUT_SEC 5

#define STAT_ABANDONED  -2
#define STAT_EPERM      -3
#define STAT_FORGED     -4
#define STAT_INTERNAL   -5

typedef struct {
    pid_t  claim;
    char   username[USERNAME_MAX];
    uint8_t digest[HASH_SZ];
} __attribute__((packed)) auth_msg;

typedef struct {
    uint8_t  challenge[CHALLENGE_SZ];
} __attribute__((packed)) chall_msg;

typedef struct {
    int   ok;
    pid_t authed_by;
} __attribute__((packed)) auth_resp;

struct peer_cred {
    pid_t pid;
    uid_t uid;
    gid_t gid;
};

static inline int sock_send(int fd, const void *buf, size_t len) {
    while (len > 0) {
        ssize_t r = send(fd, buf, len, MSG_NOSIGNAL);
        if (r <= 0) return -1;
        buf  = (const char *)buf + r;
        len -= (size_t)r;
    }
    return 0;
}

static inline int sock_recv(int fd, void *buf, size_t len) {
    while (len > 0) {
        ssize_t r = recv(fd, buf, len, MSG_WAITALL);
        if (r <= 0) return -1;
        buf  = (char *)buf + r;
        len -= (size_t)r;
    }
    return 0;
}

static inline int fetch_peer_cred(int fd, struct peer_cred *out) {
    struct ucred cr;
    socklen_t sl = sizeof(cr);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &sl) < 0)
        return -1;
    out->pid = cr.pid;
    out->uid = cr.uid;
    out->gid = cr.gid;
    return 0;
}

#endif
