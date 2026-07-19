#include "../common.h"
#include <openssl/sha.h>

static void secure_zero(void *p, size_t sz) {
    if (!p || !sz) return;
    volatile unsigned char *vp = (volatile unsigned char *)p;
    for (size_t i = 0; i < sz; i++) vp[i] = 0;
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;

    fprintf(stderr, "[rogue] pretending to be a different process\n");

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        return 1;
    }

    chall_msg chl;
    if (sock_recv(fd, &chl, sizeof(chl)) < 0) {
        perror("recv challenge");
        return 1;
    }

    uint8_t fake_hash[HASH_SZ];
    SHA256((unsigned char *)"letmein", 7, fake_hash);

    uint8_t ctx[CHALLENGE_SZ + HASH_SZ];
    memcpy(ctx, chl.challenge, CHALLENGE_SZ);
    memcpy(ctx + CHALLENGE_SZ, fake_hash, HASH_SZ);

    uint8_t combined[HASH_SZ];
    SHA256(ctx, sizeof(ctx), combined);
    secure_zero(ctx, sizeof(ctx));

    auth_msg req = {0};
    req.claim = 999999;
    strncpy(req.username, "admin", USERNAME_MAX - 1);
    memcpy(req.digest, combined, HASH_SZ);

    sock_send(fd, &req, sizeof(req));

    auth_resp resp;
    if (sock_recv(fd, &resp, sizeof(resp)) == 0) {
        if (resp.ok == STAT_FORGED)
            fprintf(stderr, "[rogue] CORRECTLY REJECTED (forgery detected)\n");
        else
            fprintf(stderr, "[rogue] UNEXPECTED: resp=%d\n", resp.ok);
    }

    close(fd);
    return 0;
}
