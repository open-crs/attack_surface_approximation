#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

static int is_random_device(int fd) {
    char path[64], link[64];
    ssize_t len;
    if (fd < 0) return 0;
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    len = readlink(path, link, sizeof(link) - 1);
    if (len <= 0) return 0;
    link[len] = '\0';
    return strcmp(link, "/dev/urandom") == 0 || strcmp(link, "/dev/random") == 0;
}

static size_t (*real_fread)(void *, size_t, size_t, FILE *) = NULL;

/* Initialize eagerly so dlsym runs before QBDI starts tracing main(). */
__attribute__((constructor)) static void init_enforcer(void) {
    real_fread = dlsym(RTLD_NEXT, "fread");
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    if (stream && is_random_device(fileno(stream))) {
        memset(ptr, 0x42, size * nmemb);
        return nmemb;
    }
    return real_fread(ptr, size, nmemb, stream);
}
