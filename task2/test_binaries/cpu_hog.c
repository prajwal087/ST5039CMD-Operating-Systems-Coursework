/*
 * cpu_hog.c - CPU-intensive test binary.
 * Consumes CPU to trigger the sandbox CPU monitor.
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main(void) {
    printf("CPU hog started (PID %d). Burning CPU...\n", getpid());
    fflush(stdout);

    volatile unsigned long long x = 0;
    for (volatile long long i = 0; i < 1LL << 40; i++) {
        x += i * i;
        if (i % 10000000 == 0) {
            printf("  still running... iteration %lld\n", i);
            fflush(stdout);
        }
    }

    printf("CPU hog done. Result = %llu\n", x);
    return 0;
}
