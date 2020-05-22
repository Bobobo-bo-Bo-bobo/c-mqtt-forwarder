#include "c-mqtt-forwarder.h"

#include <assert.h>
#include <uuid.h>
#include <stdio.h>
#include <limits.h>
#include <errno.h>
#include <stdlib.h>
#include <math.h>
#include <mosquitto.h>

#ifndef HAVE_MEMSET

#include <stddef.h>
void *memset(void *s, int c, size_t n) {
    unsigned char* p=s;
    while(n--) {
        *p++ = (unsigned char)c;
    }
    return s;
}

#else /* HAVE_MEMSET */

#include <string.h>

#endif /* HAVE_MEMSET */

#ifndef HAVE_CALLOC

void *calloc(size_t nmemb, size_t size) {
    void *ptr;
    ptr = malloc(nmemb * size);
    if (ptr != NULL) {
        memset(ptr, nmemb, size);
    };
    return ptr
};

#else /* HAVE_CALLOC */

#endif /* HAVE_CALLOC */

char *uuidgen(void) {
    char *result;
    uuid_t uuid;

    // UUID string is always 36 byte long + terminating \0
    result = (char *) malloc(37);

    // XXX: it is critical if we don't have enough memory to allocate 37 byte
    assert(result != NULL);

    uuid_generate(uuid);
    uuid_unparse(uuid, result);
    return result;
}

long str2long(const char *str) {
    char *remain;
    long result;

    result = strtol(str, &remain, 10);
    if ((errno == ERANGE && (result == LONG_MAX || result == LONG_MIN)) || (errno != 0 && result == 0)) {
        log_error("Can't convert %s to long", str);
        return LONG_MIN;
    }
    if (str == remain) {
        log_error("Can't convert %s to long", str);
        return LONG_MIN;
    }
    if (*remain != 0) {
        log_error("Can't convert %s to long", str);
        return LONG_MIN;
    }
    return result;
}

void destroy_configuration(struct configuration *cfg) {
    if (!cfg) {
        return;
    }
}

int float_len6(const double d) {
    int pre_dig;

    // NOTE: Comparing floats is not correct, but we simply
    // prevent negative numbers on log(d)
    if (fabs(d) < 1.0) {
        pre_dig = 1;
    } else {
        pre_dig = (int) log(fabs(d)) / log(10.0);
    }
    if (d < 0.0) {
        pre_dig ++; // add minus sign
    }
    return pre_dig + 7; // 6 digits after . + "."
}

