#ifndef __C_MQTT_FORWAREDER_PROCESS_MSGS_H__
#define __C_MQTT_FORWAREDER_PROCESS_MSGS_H__

#include "c-mqtt-forwarder.h"

unsigned int message_queue_length(struct mqtt_configuration *);
void destroy_msg(struct message *);
void process_message_queue(struct mqtt_configuration *);

#endif
