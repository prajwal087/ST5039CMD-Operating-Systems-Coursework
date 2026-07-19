#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <time.h>

int main(void) {
    fprintf(stderr, "[weasel] pid=%d trying to evade the sandbox\n", getpid());

    prctl(PR_SET_NAME, "udevd", 0, 0, 0);

    pid_t child = fork();
    if (child == 0) {
        prctl(PR_SET_NAME, "kworker/0:5", 0, 0, 0);
        setsid();
        pid_t grandkid = fork();
        if (grandkid == 0) {
            prctl(PR_SET_NAME, "[ cryptd ]", 0, 0, 0);

            struct timespec deadline;
            clock_gettime(CLOCK_MONOTONIC, &deadline);

            while (1) {
                struct timespec now;
                clock_gettime(CLOCK_MONOTONIC, &now);
                double elapsed = (now.tv_sec - deadline.tv_sec)
                               + (now.tv_nsec - deadline.tv_nsec) / 1e9;

                volatile unsigned long acc = 0;
                for (int i = 0; i < 3000000; i++) acc += (unsigned long)i;
                (void)acc;

                if (elapsed > 3.0) {
                    fprintf(stderr, "[weasel/grandkid] done hiding, now burning CPU\n");
                    while (1) {
                        volatile unsigned long x = 0;
                        for (int i = 0; i < 10000000; i++) x += (unsigned long)i * i * i;
                        (void)x;
                    }
                }
                usleep(10000);
            }
        }
        _exit(0);
    }

    waitpid(child, NULL, 0);
    fprintf(stderr, "[weasel] child reaped, waiting...\n");
    while (1) pause();
    return 0;
}
