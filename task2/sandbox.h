#ifndef SANDBOX_H
#define SANDBOX_H

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <sys/eventfd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <stdint.h>
#include <poll.h>

#define LOG_PATH      "sandbox.log"
#define PROC_STAT_PFX "/proc/"
#define PROC_STAT_SFX "/stat"
#define PROC_STATUS_SFX "/status"

enum monitor_state {
    MON_IDLE       = 0,
    MON_ACTIVE     = 1,
    MON_WARN       = 2,
    MON_TERM_SIG   = 3,
    MON_TERM_KILL  = 4,
    MON_DONE       = 5
};

enum term_reason {
    TR_NONE       = 0,
    TR_WALL_CLOCK = 1,
    TR_CPU_LIMIT  = 2,
    TR_RSS_LIMIT  = 4,
    TR_SELF_EXIT  = 8,
    TR_USER_REQ   = 16
};

typedef struct {
    int       wall_sec;
    int       cpu_pct;
    size_t    rss_kb;
    int       grace_ms;
    int       log_fd;
    pid_t     child;
    int       pipe_wake;
    enum monitor_state state;
    atomic_int         term_reason;
    atomic_int         term_attempted;
} sandbox_cfg;

typedef struct {
    int    pid;
    long   utime_ticks;
    long   stime_ticks;
    long   vctx;
    long   nvctx;
    long   rss_pages;
    long   threads;
    long   starttime_ticks;
} proc_snapshot;

int    parse_proc_stat(pid_t pid, proc_snapshot *out);
int    parse_proc_status(pid_t pid, proc_snapshot *out);
double ticks_to_sec(long ticks);
void   json_log(int fd, const char *event, pid_t child,
                const char *key, const char *val);
void   json_log_int(int fd, const char *event, pid_t child,
                    const char *key, long val);
#endif
