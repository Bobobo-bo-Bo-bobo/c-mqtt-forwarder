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
#ifndef __C_MQTT_FORWARDER_PARSE_CFG_H__
#define __C_MQTT_FORWARDER_PARSE_CFG_H__

#include "c-mqtt-forwarder.h"

void set_mqtt_configuration_defaults(struct mqtt_configuration *);
void destroy_mqtt_configuration(struct mqtt_configuration *);
void destroy_configuration(struct configuration *);
char *read_configuration_file(const char *);
struct configuration *parse_config_file(const char *);
bool validate_configuration(const struct configuration *);
void set_mqtt_ca(struct mqtt_configuration *);

#ifdef DEBUG
void dump_mqtt_configuration(const struct mqtt_configuration *);
void dump_configuration(const struct configuration *);
#endif

#endif
