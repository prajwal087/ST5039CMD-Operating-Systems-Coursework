/*
 * memory_leak.c - Memory-intensive test binary.
 * Allocates memory rapidly to trigger the sandbox memory monitor.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(void) {
    printf("Memory leaker started (PID %d). Allocating memory...\n",
           getpid());
    fflush(stdout);

    for (int i = 0; i < 100; i++) {
        size_t size = 10 * 1024 * 1024;
        char *p = malloc(size);
        if (p) {
            memset(p, 0xFF, size);
            printf("  allocated %zu MB (block %d)\n", size / 1024 / 1024, i);
        } else {
            printf("  malloc failed at block %d\n", i);
            break;
        }
        fflush(stdout);
        usleep(500000);
    }

    printf("Memory leaker done.\n");
    return 0;
}
