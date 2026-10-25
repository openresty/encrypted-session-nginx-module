/* Test-only RAND_bytes failure injection, loaded with LD_PRELOAD. */
#define _GNU_SOURCE
#include <dlfcn.h>


static int fail_random;


void
encrypted_session_test_rand_fail(int enabled)
{
    fail_random = enabled;
}


int
RAND_bytes(unsigned char *buf, int len)
{
    int (*real_rand_bytes)(unsigned char *, int);

    if (fail_random) {
        return 0;
    }

    real_rand_bytes = dlsym(RTLD_NEXT, "RAND_bytes");
    return real_rand_bytes(buf, len);
}
