/*
 * This file is part of c-mqtt-forwarder
 *
 * Copyright (C) 2020 by Andreas Maus <maus@ypbind.de>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
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
        LOG_ERROR("Can't convert %s to long", str);
        return LONG_MIN;
    }
    if (str == remain) {
        LOG_ERROR("Can't convert %s to long", str);
        return LONG_MIN;
    }
    if (*remain != 0) {
        LOG_ERROR("Can't convert %s to long", str);
        return LONG_MIN;
    }
    return result;
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

