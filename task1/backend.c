#include "common.h"
#include <openssl/sha.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <sys/resource.h>
#include <pthread.h>
#include <poll.h>
#include <sys/signalfd.h>
#include <time.h>
#include <stdatomic.h>

#define STORE_SZ 16384
#define BACKEND_UID 65534
#define BACKEND_GID 65534

static atomic_int g_terminate = 0;

static void drain_peer(int fd) {
    char sink[256];
    struct pollfd p = { .fd = fd, .events = POLLIN };
    while (poll(&p, 1, 200) > 0)
        recv(fd, sink, sizeof(sink), 0);
}

struct auth_slot {
    char   username[USERNAME_MAX];
    uint8_t stored_hash[HASH_SZ];
    int     occupied;
};

static struct auth_slot *g_store = NULL;

static void secure_zero(void *p, size_t sz) {
    if (!p || !sz) return;
    volatile unsigned char *vp = (volatile unsigned char *)p;
    for (size_t i = 0; i < sz; i++) vp[i] = 0;
}

static int load_credentials(void) {
    g_store = mmap(NULL, STORE_SZ, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS | MAP_LOCKED | MAP_POPULATE,
                   -1, 0);
    if (g_store == MAP_FAILED) return -1;

    mlock(g_store, STORE_SZ);

    int n = 0;
    char line[512];
    FILE *fp = fopen("passwd.store", "r");
    if (!fp) return -1;
    while (fgets(line, sizeof(line), fp)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        char *sep = strchr(line, ':');
        if (!sep) continue;
        *sep = 0;
        if (n >= (int)(STORE_SZ / sizeof(struct auth_slot))) break;
        strncpy(g_store[n].username, line, USERNAME_MAX - 1);
        SHA256((unsigned char*)(sep + 1), strlen(sep + 1), g_store[n].stored_hash);
        g_store[n].occupied = 1;
        n++;
    }
    fclose(fp);
    return n;
}

static int validate_challenge(auth_msg *req, chall_msg *chl) {
    if (!req || !chl) return -1;

    struct auth_slot *slot = NULL;
    int max_slots = STORE_SZ / sizeof(struct auth_slot);
    for (int i = 0; i < max_slots; i++) {
        if (g_store[i].occupied &&
            strncmp(g_store[i].username, req->username, USERNAME_MAX - 1) == 0) {
            slot = &g_store[i];
            break;
        }
    }
    if (!slot) return -1;

    uint8_t ctx_inp[CHALLENGE_SZ + HASH_SZ];
    memcpy(ctx_inp, chl->challenge, CHALLENGE_SZ);
    memcpy(ctx_inp + CHALLENGE_SZ, slot->stored_hash, HASH_SZ);

    uint8_t expected[HASH_SZ];
    SHA256(ctx_inp, sizeof(ctx_inp), expected);

    int match = 1;
    for (size_t i = 0; i < HASH_SZ; i++)
        if (expected[i] != req->digest[i]) { match = 0; break; }

    secure_zero(ctx_inp, sizeof(ctx_inp));
    return match ? 0 : -1;
}

static void drop_privileges(void) {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        perror("PR_SET_NO_NEW_PRIVS");
        exit(EXIT_FAILURE);
    }

    /* Drop GID first, then UID — once UID changes we lose CAP_SETGID */
    if (setresgid(BACKEND_GID, BACKEND_GID, BACKEND_GID) < 0) {
        perror("setresgid");
        exit(EXIT_FAILURE);
    }
    if (setresuid(BACKEND_UID, BACKEND_UID, BACKEND_UID) < 0) {
        perror("setresuid");
        exit(EXIT_FAILURE);
    }

    /* Then drop all capabilities so we can never regain privileges */
    struct __user_cap_header_struct cap_hdr = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0
    };
    struct __user_cap_data_struct cap_data[2] = {0};
    if (capset(&cap_hdr, cap_data) < 0) {
        perror("capset (drop all)");
        exit(EXIT_FAILURE);
    }
}

static void *signal_watcher(void *arg) {
    (void)arg;
    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, SIGTERM);
    sigaddset(&ss, SIGINT);

    int sfd = signalfd(-1, &ss, SFD_CLOEXEC);
    if (sfd < 0) { perror("signalfd"); return NULL; }

    struct signalfd_siginfo si;
    while (1) {
        if (read(sfd, &si, sizeof(si)) != sizeof(si)) continue;
        if (si.ssi_signo == SIGTERM || si.ssi_signo == SIGINT) {
            atomic_store(&g_terminate, 1);
            break;
        }
    }
    close(sfd);
    return NULL;
}

int main(int argc, char **argv) {
    (void)argc; (void)argv;

    sigset_t block_all;
    sigfillset(&block_all);
    pthread_sigmask(SIG_SETMASK, &block_all, NULL);

    fprintf(stderr, "[backend] pid=%d starting\n", getpid());
    fprintf(stderr, "[backend] initial euid=%d egid=%d\n", geteuid(), getegid());

    int ncreds = load_credentials();
    if (ncreds <= 0) {
        fprintf(stderr, "no credentials loaded (create passwd.store)\n");
        exit(STAT_INTERNAL);
    }
    fprintf(stderr, "[backend] loaded %d credential(s)\n", ncreds);

    unlink(SOCK_PATH);
    int srv = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (srv < 0) { perror("socket"); exit(STAT_INTERNAL); }

    struct sockaddr_un addr = {.sun_family = AF_UNIX};
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(srv);
        exit(STAT_INTERNAL);
    }

    chmod(SOCK_PATH, 0666);

    if (listen(srv, 5) < 0) {
        perror("listen");
        close(srv);
        exit(STAT_INTERNAL);
    }

    drop_privileges();
    fprintf(stderr, "[backend] privileges dropped. euid=%d egid=%d\n",
            geteuid(), getegid());

    pthread_t sig_thr;
    pthread_create(&sig_thr, NULL, signal_watcher, NULL);
    pthread_detach(sig_thr);

    while (!atomic_load(&g_terminate)) {
        struct sockaddr_un client_addr;
        socklen_t client_len = sizeof(client_addr);
        int peer = accept4(srv, (struct sockaddr *)&client_addr,
                           &client_len, SOCK_CLOEXEC);
        if (peer < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }

        struct peer_cred cred;
        if (fetch_peer_cred(peer, &cred) < 0) {
            fprintf(stderr, "PEERCRED fetch failed\n");
            drain_peer(peer);
            close(peer);
            continue;
        }
        fprintf(stderr, "[backend] connection from pid=%d uid=%d\n",
                cred.pid, cred.uid);

        chall_msg chl;
        int cfd = open("/dev/urandom", O_RDONLY);
        if (cfd < 0 || read(cfd, chl.challenge, CHALLENGE_SZ) != CHALLENGE_SZ) {
            fprintf(stderr, "challenge generation failed\n");
            if (cfd >= 0) close(cfd);
            drain_peer(peer);
            close(peer);
            continue;
        }
        close(cfd);

        if (sock_send(peer, &chl, sizeof(chl)) < 0) {
            perror("send challenge");
            close(peer);
            continue;
        }

        auth_msg req;
        if (sock_recv(peer, &req, sizeof(req)) < 0) {
            perror("recv auth_msg");
            close(peer);
            continue;
        }

        auth_resp resp = {0};
        if (req.claim != cred.pid) {
            fprintf(stderr, "PID mismatch: claim=%d actual=%d\n",
                    req.claim, cred.pid);
            resp.ok = STAT_FORGED;
        } else if (validate_challenge(&req, &chl) == 0) {
            resp.ok = 1;
            resp.authed_by = getpid();
        } else {
            resp.ok = 0;
        }

        sock_send(peer, &resp, sizeof(resp));
        secure_zero(&req, sizeof(req));
        secure_zero(&chl, sizeof(chl));
        close(peer);

        if (resp.ok == 1)
            fprintf(stderr, "[backend] AUTH OK pid=%d\n", cred.pid);
        else if (resp.ok == STAT_FORGED)
            fprintf(stderr, "[backend] FORGERY DETECTED pid=%d\n", cred.pid);
        else if (resp.ok == STAT_EPERM)
            fprintf(stderr, "[backend] UID UNAUTHORIZED pid=%d uid=%d\n", cred.pid, cred.uid);
        else
            fprintf(stderr, "[backend] AUTH FAIL pid=%d\n", cred.pid);
    }

    fprintf(stderr, "[backend] shutting down\n");
    close(srv);
    unlink(SOCK_PATH);

    secure_zero(g_store, STORE_SZ);
    munlock(g_store, STORE_SZ);
    munmap(g_store, STORE_SZ);

    return 0;
}
