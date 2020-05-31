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
