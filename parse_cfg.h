#ifndef __C_MQTT_FORWARDER_PARSE_CFG_H__
#define __C_MQTT_FORWARDER_PARSE_CFG_H__

#include "c-mqtt-forwarder.h"

void set_mqtt_configuration_defaults(struct mqtt_configuration *);
void destroy_mqtt_configuration(struct mqtt_configuration *);
void destroy_configuration(struct configuration *);
char *read_configuration_file(const char *);
struct configuration *parse_config_file(const char *);
bool validate_configuration(const struct configuration *);

#ifdef DEBUG
void dump_mqtt_configuration(const struct mqtt_configuration *);
void dump_configuration(const struct configuration *);
#endif

#endif
