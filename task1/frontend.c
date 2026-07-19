#include "common.h"
#include <openssl/sha.h>
#include <termios.h>
#include <poll.h>
#include <time.h>

static void secure_zero(void *p, size_t sz) {
    if (!p || !sz) return;
    volatile unsigned char *vp = (volatile unsigned char *)p;
    for (size_t i = 0; i < sz; i++) vp[i] = 0;
}

static int read_password(char *buf, size_t sz) {
    if (!isatty(STDIN_FILENO)) {
        if (!fgets(buf, sz, stdin)) return -1;
        buf[strcspn(buf, "\n")] = 0;
        return (int)strlen(buf);
    }

    struct termios old, raw;
    if (tcgetattr(STDIN_FILENO, &old) < 0) return -1;
    raw = old;
    raw.c_lflag &= ~(ECHO | ICANON);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) < 0) return -1;

    size_t pos = 0;
    while (pos < sz - 1) {
        char c;
        if (read(STDIN_FILENO, &c, 1) != 1) break;
        if (c == '\n' || c == '\r') break;
        if (c == 127 || c == '\b') {
            if (pos > 0) pos--;
            continue;
        }
        buf[pos++] = c;
    }
    buf[pos] = 0;

    tcsetattr(STDIN_FILENO, TCSANOW, &old);
    return (int)pos;
}

static int try_auth(const char *username, const char *password) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { perror("socket"); return -1; }

    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);

    struct timeval tv = {.tv_sec = AUTH_TIMEOUT_SEC, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    chall_msg chl;
    if (sock_recv(fd, &chl, sizeof(chl)) < 0) {
        perror("recv challenge");
        close(fd);
        return -1;
    }

    uint8_t pw_hash[HASH_SZ];
    SHA256((unsigned char *)password, strlen(password), pw_hash);

    uint8_t ctx_inp[CHALLENGE_SZ + HASH_SZ];
    memcpy(ctx_inp, chl.challenge, CHALLENGE_SZ);
    memcpy(ctx_inp + CHALLENGE_SZ, pw_hash, HASH_SZ);

    uint8_t combined[HASH_SZ];
    SHA256(ctx_inp, sizeof(ctx_inp), combined);
    secure_zero(ctx_inp, sizeof(ctx_inp));

    auth_msg req = {0};
    req.claim = getpid();
    strncpy(req.username, username, USERNAME_MAX - 1);
    memcpy(req.digest, combined, HASH_SZ);

    if (sock_send(fd, &req, sizeof(req)) < 0) {
        perror("send auth_msg");
        close(fd);
        return -1;
    }

    auth_resp resp = {0};
    if (sock_recv(fd, &resp, sizeof(resp)) < 0) {
        perror("recv response");
        close(fd);
        return -1;
    }

    secure_zero(&req, sizeof(req));
    close(fd);
    return resp.ok;
}

int main(int argc, char **argv) {
    const char *username = "student";
    if (argc > 1) username = argv[1];

    fprintf(stderr, "[frontend] auth request for '%s'\n", username);

    int rc = -1;
    for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
        fprintf(stderr, "[frontend] attempt %d/%d\n", attempt, MAX_RETRIES);
        fprintf(stderr, "[frontend] password: ");
        fflush(stderr);

        char pw[256];
        int pwlen = read_password(pw, sizeof(pw));
        if (pwlen < 0) {
            fprintf(stderr, "\ninput error\n");
            exit(1);
        }
        fprintf(stderr, "\n");

        rc = try_auth(username, pw);
        secure_zero(pw, sizeof(pw));
        if (rc == 1) break;
        if (rc == STAT_FORGED) {
            fprintf(stderr, "[frontend] connection integrity failure\n");
            break;
        }
        if (rc == STAT_EPERM) {
            fprintf(stderr, "[frontend] unauthorised identity\n");
            break;
        }
        if (rc < 0 && attempt < MAX_RETRIES) {
            fprintf(stderr, "[frontend] retrying...\n");
            sleep(1);
        }
    }

    switch (rc) {
    case 1:
        printf("AUTH_GRANTED\n");
        return 0;
    case 0:
        printf("AUTH_DENIED\n");
        return 1;
    case STAT_FORGED:
        printf("CONNECTION_TAMPERED\n");
        return 2;
    case STAT_EPERM:
        printf("CONNECTION_UNAUTHORISED\n");
        return 4;
    default:
        printf("AUTH_UNAVAILABLE\n");
        return 3;
    }
}
