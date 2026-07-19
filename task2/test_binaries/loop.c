#include <unistd.h>
#include <stdio.h>
#include <time.h>

int main(void) {
    fprintf(stderr, "[loop] pid=%d spinning forever\n", getpid());
    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);

    while (1) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        double elapsed = (now.tv_sec - deadline.tv_sec)
                       + (now.tv_nsec - deadline.tv_nsec) / 1e9;

        volatile unsigned long acc = 0;
        for (int i = 0; i < 5000000; i++) acc += (unsigned long)i * i;
        (void)acc;

        if ((unsigned long)elapsed % 2 == 0)
            write(1, ".", 1);
    }
    return 0;
}
