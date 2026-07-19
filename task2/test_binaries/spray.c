#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define CHUNK_SZ (1024 * 1024)  /* 1 MB */

int main(void) {
    fprintf(stderr, "[spray] pid=%d allocating memory until death\n", getpid());

    unsigned long total = 0;
    while (1) {
        void *p = mmap(NULL, CHUNK_SZ, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
                       -1, 0);
        if (p == MAP_FAILED) {
            fprintf(stderr, "[spray] OOM at %lu MB\n", total);
            break;
        }
        memset(p, 0x41, CHUNK_SZ);
        total++;
        if (total % 100 == 0)
            fprintf(stderr, "[spray] allocated %lu MB\n", total);
    }

    fprintf(stderr, "[spray] sleeping forever with what we have\n");
    while (1) pause();
    return 0;
}
