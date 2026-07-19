/*
 * benign.c - A well-behaved test binary for the sandbox.
 * Prints a message and exits quickly.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    printf("Benign binary started (PID %d). Doing harmless work...\n",
           getpid());
    fflush(stdout);
    sleep(1);
    printf("Benign binary done. Exiting.\n");
    return 0;
}
