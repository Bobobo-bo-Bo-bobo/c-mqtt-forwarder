#ifndef __C_MQTT_FORWARDER_UTIL_H__
#define __C_MQTT_FORWARDER_UTIL_H__

#include "c-mqtt-forwarder.h"

char *uuidgen(void);

#ifndef HAVE_MEMSET

#include <stddef.h>
void *memset(void *, int, size_t);

#else /* HAVE_MEMSET */

#include <string.h>

#endif /* HAVE_MEMSET */

long str2long(const char *);
void destroy_configuration(struct configuration *);
int float_len6(const double);

#endif /* __C_MQTT_FORWARDER_UTIL_H__ */
