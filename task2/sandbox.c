#include "sandbox.h"

static long g_hz = 0;

static long sys_hz(void) {
    if (!g_hz) { g_hz = sysconf(_SC_CLK_TCK); if (g_hz <= 0) g_hz = 100; }
    return g_hz;
}

double ticks_to_sec(long ticks) {
    return (double)ticks / (double)sys_hz();
}

void json_log(int fd, const char *event, pid_t child,
              const char *key, const char *val) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    char buf[1024];
    int n = snprintf(buf, sizeof(buf),
        "{\"t\":%ld.%03ld,\"ev\":\"%s\",\"pid\":%d,\"%s\":\"%s\"}\n",
        ts.tv_sec, ts.tv_nsec / 1000000, event, child, key, val);
    write(fd, buf, (size_t)(n < 0 ? 0 : (n > (int)sizeof(buf)-1 ? (int)sizeof(buf)-1 : n)));
}

void json_log_int(int fd, const char *event, pid_t child,
                  const char *key, long val) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    char buf[1024];
    int n = snprintf(buf, sizeof(buf),
        "{\"t\":%ld.%03ld,\"ev\":\"%s\",\"pid\":%d,\"%s\":%ld}\n",
        ts.tv_sec, ts.tv_nsec / 1000000, event, child, key, val);
    write(fd, buf, (size_t)(n < 0 ? 0 : (n > (int)sizeof(buf)-1 ? (int)sizeof(buf)-1 : n)));
}

int parse_proc_stat(pid_t pid, proc_snapshot *out) {
    memset(out, 0, sizeof(*out));
    out->pid = pid;

    char path[64];
    snprintf(path, sizeof(path), PROC_STAT_PFX "%d" PROC_STAT_SFX, pid);

    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    char buf[8192];
    ssize_t nr = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (nr <= 0) return -1;
    buf[nr] = 0;

    char *p = buf;
    while (*p && *p != ')') p++;
    if (*p) p += 2;
    while (*p == ' ') p++;

    long rss_pages = 0;
    int matched = sscanf(p,
        "%*c %*d %*d %*d %*d %*d "
        "%*u %*u %*u %*u %*u %*u %*u "
        "%ld %ld "                             /* field 11: utime, 12: stime */
        "%*d %*d %*d %*d "
        "%*u %*u %*d %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u %*u "
        "%*d %*d "
        "%*u %*u %ld",                         /* field 39: rss pages */
        &out->utime_ticks, &out->stime_ticks, &rss_pages);

    if (matched == 3) {
        out->rss_pages = rss_pages;
        return 0;
    }
    return -1;
}

int parse_proc_status(pid_t pid, proc_snapshot *out) {
    char path[64];
    snprintf(path, sizeof(path), PROC_STAT_PFX "%d" PROC_STATUS_SFX, pid);

    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    char buf[4096];
    ssize_t nr = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (nr <= 0) return -1;
    buf[nr] = 0;

    char *ln = buf;
    while (ln && *ln) {
        char *nl = strchr(ln, '\n');
        if (nl) *nl = 0;
        if (strncmp(ln, "Threads:", 8) == 0)
            out->threads = atol(ln + 8);
        if (strncmp(ln, "voluntary_ctxt_switches:", 24) == 0)
            out->vctx = atol(ln + 24);
        if (strncmp(ln, "nonvoluntary_ctxt_switches:", 27) == 0)
            out->nvctx = atol(ln + 27);
        ln = nl ? nl + 1 : NULL;
    }
    return 0;
}

static void set_resource_limits(int cpu_pct, size_t rss_kb, int wall_sec) {
    (void)cpu_pct; (void)wall_sec;
    struct rlimit rl;

    /* RLIMIT_CPU commented out: kernel SIGXCPU kills child before
       monitoring threads can log the event. Wall-clock monitoring
       in the parent handles time enforcement instead.
    rl.rlim_cur = rl.rlim_max = (rlim_t)wall_sec + 2;
    setrlimit(RLIMIT_CPU, &rl); */

    rl.rlim_cur = rl.rlim_max = (rlim_t)(rss_kb * 1024 * 2);
    setrlimit(RLIMIT_AS, &rl);

    rl.rlim_cur = rl.rlim_max = 256;
    setrlimit(RLIMIT_NPROC, &rl);

    rl.rlim_cur = rl.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &rl);
}

static void *monitor_wallclock(void *arg) {
    sandbox_cfg *cfg = (sandbox_cfg *)arg;
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);

    while (1) {
        int reason = atomic_load(&cfg->term_reason);
        if (reason & (TR_SELF_EXIT | TR_USER_REQ)) break;
        if (atomic_load(&cfg->term_attempted)) break;

        clock_gettime(CLOCK_MONOTONIC, &now);
        double elapsed = (now.tv_sec - start.tv_sec)
                       + (now.tv_nsec - start.tv_nsec) / 1e9;

        if (elapsed > cfg->wall_sec) {
            char buf[32];
            snprintf(buf, sizeof(buf), "%.2f", elapsed);
            json_log(cfg->log_fd, "wallclock_exceeded", cfg->child,
                     "elapsed_s", buf);
            atomic_store(&cfg->term_reason,
                         atomic_load(&cfg->term_reason) | TR_WALL_CLOCK);
            break;
        }
        usleep(50000);
    }
    return NULL;
}

static void *monitor_cpu(void *arg) {
    sandbox_cfg *cfg = (sandbox_cfg *)arg;
    proc_snapshot prev = {0}, curr = {0};
    struct timespec t_prev, t_curr;

    if (parse_proc_stat(cfg->child, &prev) < 0) return NULL;
    clock_gettime(CLOCK_MONOTONIC, &t_prev);

    while (1) {
        int reason = atomic_load(&cfg->term_reason);
        if (reason & (TR_SELF_EXIT | TR_USER_REQ)) break;
        if (atomic_load(&cfg->term_attempted)) break;

        usleep(250000);

        if (parse_proc_stat(cfg->child, &curr) < 0) {
            if (errno == ENOENT) {
                atomic_store(&cfg->term_reason,
                             atomic_load(&cfg->term_reason) | TR_SELF_EXIT);
            }
            break;
        }
        clock_gettime(CLOCK_MONOTONIC, &t_curr);

        double dt = (t_curr.tv_sec - t_prev.tv_sec)
                  + (t_curr.tv_nsec - t_prev.tv_nsec) / 1e9;
        if (dt <= 0) { prev = curr; t_prev = t_curr; continue; }

        long d_utime = curr.utime_ticks - prev.utime_ticks;
        long d_stime = curr.stime_ticks - prev.stime_ticks;
        double cpu_frac = (double)(d_utime + d_stime) / (sys_hz() * dt);
        int pct = (int)(cpu_frac * 100.0);

        if (pct > cfg->cpu_pct) {
            json_log_int(cfg->log_fd, "cpu_exceeded", cfg->child,
                         "cpu_pct", pct);
            atomic_store(&cfg->term_reason,
                         atomic_load(&cfg->term_reason) | TR_CPU_LIMIT);
            break;
        }

        json_log_int(cfg->log_fd, "cpu_sample", cfg->child, "pct", pct);

        prev = curr;
        t_prev = t_curr;
    }
    return NULL;
}

static void *monitor_memory(void *arg) {
    sandbox_cfg *cfg = (sandbox_cfg *)arg;

    while (1) {
        int reason = atomic_load(&cfg->term_reason);
        if (reason & (TR_SELF_EXIT | TR_USER_REQ)) break;
        if (atomic_load(&cfg->term_attempted)) break;

        usleep(300000);

        proc_snapshot ps = {0};
        if (parse_proc_stat(cfg->child, &ps) < 0) break;
        if (parse_proc_status(cfg->child, &ps) < 0) continue;

        size_t rss_kb = (size_t)ps.rss_pages * (size_t)sysconf(_SC_PAGE_SIZE) / 1024;

        json_log_int(cfg->log_fd, "mem_sample", cfg->child, "rss_kb", (long)rss_kb);
        json_log_int(cfg->log_fd, "mem_sample", cfg->child, "threads", ps.threads);
        json_log_int(cfg->log_fd, "mem_sample", cfg->child, "ctx_v", ps.vctx);
        json_log_int(cfg->log_fd, "mem_sample", cfg->child, "ctx_nv", ps.nvctx);

        if (rss_kb > cfg->rss_kb) {
            json_log_int(cfg->log_fd, "rss_exceeded", cfg->child,
                         "rss_kb", (long)rss_kb);
            atomic_store(&cfg->term_reason,
                         atomic_load(&cfg->term_reason) | TR_RSS_LIMIT);
            break;
        }
    }
    return NULL;
}

static int launch_child(const char *bin, char *const argv[], sandbox_cfg *cfg) {
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return -1; }

    if (pid == 0) {
        prctl(PR_SET_PDEATHSIG, SIGKILL);

        int null_fd = open("/dev/null", O_RDWR);
        if (null_fd >= 0) {
            dup2(null_fd, STDIN_FILENO);
            dup2(null_fd, STDOUT_FILENO);
            dup2(null_fd, STDERR_FILENO);
            if (null_fd > 2) close(null_fd);
        }

        set_resource_limits(cfg->cpu_pct, cfg->rss_kb, cfg->wall_sec);

        if (execve(bin, argv, (char *[]){NULL}) < 0) {
            perror("execve");
            _exit(127);
        }
    }

    cfg->child = pid;
    json_log_int(cfg->log_fd, "child_spawned", pid, "pid", pid);
    return 0;
}

static void terminate_child(sandbox_cfg *cfg) {
    if (atomic_exchange(&cfg->term_attempted, 1)) return;

    int reason = atomic_load(&cfg->term_reason);

    if (reason & TR_SELF_EXIT) {
        json_log(cfg->log_fd, "child_exited", cfg->child, "status", "self");
        return;
    }

    json_log_int(cfg->log_fd, "terminating", cfg->child, "reason_mask", reason);

    if (kill(cfg->child, SIGTERM) == 0) {
        json_log(cfg->log_fd, "sent_sigterm", cfg->child, "", "");
        usleep(cfg->grace_ms * 1000);
    }

    if (kill(cfg->child, 0) == 0) {
        kill(cfg->child, SIGKILL);
        json_log(cfg->log_fd, "sent_sigkill", cfg->child, "", "");
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <binary> [args...]\n", argv[0]);
        fprintf(stderr, "  env: SANDBOX_WALL=%d SANDBOX_CPU=%d SANDBOX_RSS=%d SANDBOX_GRACE=%d\n",
                5, 80, 256000, 500);
        return 1;
    }

    sandbox_cfg cfg = {
        .wall_sec  = 5,
        .cpu_pct   = 80,
        .rss_kb    = 256000,
        .grace_ms  = 500,
        .child     = -1,
        .state     = MON_IDLE,
        .term_reason = ATOMIC_VAR_INIT(0),
        .term_attempted = ATOMIC_VAR_INIT(0),
    };

    char *ev = getenv("SANDBOX_WALL");
    if (ev) cfg.wall_sec = atoi(ev);
    ev = getenv("SANDBOX_CPU");
    if (ev) cfg.cpu_pct = atoi(ev);
    ev = getenv("SANDBOX_RSS");
    if (ev) cfg.rss_kb = (size_t)atol(ev);
    ev = getenv("SANDBOX_GRACE");
    if (ev) cfg.grace_ms = atoi(ev);

    if (cfg.wall_sec <= 0 || cfg.cpu_pct <= 0 || cfg.rss_kb <= 0) {
        fprintf(stderr, "invalid limits\n");
        return 1;
    }

    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, SIGCHLD);
    sigaddset(&ss, SIGINT);
    sigaddset(&ss, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &ss, NULL);

    cfg.log_fd = open(LOG_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (cfg.log_fd < 0) { perror("log"); return 1; }

    json_log(cfg.log_fd, "sandbox_start", 0, "limits",
             (char[128]){0});
    char limits[256];
    snprintf(limits, sizeof(limits),
             "wall=%ds cpu=%d%% rss=%zukB grace=%dms",
             cfg.wall_sec, cfg.cpu_pct, cfg.rss_kb, cfg.grace_ms);
    json_log(cfg.log_fd, "sandbox_start", 0, "limits", limits);

    int pipe_wake[2];
    if (pipe2(pipe_wake, O_CLOEXEC) < 0) { perror("pipe2"); return 1; }
    cfg.pipe_wake = pipe_wake[1];

    if (launch_child(argv[1], argv + 1, &cfg) < 0) {
        close(cfg.log_fd);
        return 1;
    }

    int sfd = signalfd(-1, &ss, SFD_CLOEXEC);
    if (sfd < 0) { perror("signalfd"); return 1; }

    pthread_t thr_wall, thr_cpu, thr_mem;
    pthread_create(&thr_wall, NULL, monitor_wallclock, &cfg);
    pthread_create(&thr_cpu, NULL, monitor_cpu, &cfg);
    pthread_create(&thr_mem, NULL, monitor_memory, &cfg);

    while (1) {
        struct signalfd_siginfo si;
        struct pollfd pfd = { .fd = sfd, .events = POLLIN };

        int pr = poll(&pfd, 1, 100);
        if (pr > 0 && (pfd.revents & POLLIN)) {
            if (read(sfd, &si, sizeof(si)) == sizeof(si)) {
                if (si.ssi_signo == SIGCHLD) {
                    int wstatus;
                    waitpid(cfg.child, &wstatus, WNOHANG);
                    if (WIFEXITED(wstatus))
                        json_log_int(cfg.log_fd, "child_exit", cfg.child,
                                     "code", WEXITSTATUS(wstatus));
                    else if (WIFSIGNALED(wstatus))
                        json_log_int(cfg.log_fd, "child_killed", cfg.child,
                                     "sig", WTERMSIG(wstatus));
                    atomic_store(&cfg.term_reason,
                                 atomic_load(&cfg.term_reason) | TR_SELF_EXIT);
                    break;
                }
                if (si.ssi_signo == SIGINT || si.ssi_signo == SIGTERM) {
                    atomic_store(&cfg.term_reason,
                                 atomic_load(&cfg.term_reason) | TR_USER_REQ);
                    break;
                }
            }
        }

        int reason = atomic_load(&cfg.term_reason);
        if (reason & (TR_WALL_CLOCK | TR_CPU_LIMIT | TR_RSS_LIMIT))
            break;
    }

    if (cfg.child > 0 && !(atomic_load(&cfg.term_reason) & TR_SELF_EXIT))
        terminate_child(&cfg);

    if (cfg.child > 0) {
        int wstatus;
        waitpid(cfg.child, &wstatus, 0);
        json_log_int(cfg.log_fd, "final_status", cfg.child,
                     "waitpid", wstatus);
    }

    int final_reason = atomic_load(&cfg.term_reason);

    close(cfg.log_fd);
    close(sfd);

    char reason_str[64] = "terminated";
    if (final_reason & TR_WALL_CLOCK) snprintf(reason_str, sizeof(reason_str), "wall_clock");
    else if (final_reason & TR_CPU_LIMIT) snprintf(reason_str, sizeof(reason_str), "cpu_limit");
    else if (final_reason & TR_RSS_LIMIT) snprintf(reason_str, sizeof(reason_str), "rss_limit");
    else if (final_reason & TR_SELF_EXIT) snprintf(reason_str, sizeof(reason_str), "self_exit");
    else if (final_reason & TR_USER_REQ) snprintf(reason_str, sizeof(reason_str), "user_request");

    printf("[sandbox] child=%d reason=%s mask=%d\n",
           cfg.child, reason_str, final_reason);

    return (final_reason & TR_SELF_EXIT) ? 0 : 1;
}
