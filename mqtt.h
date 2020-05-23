#ifndef __C_MQTT_FORWARDER_MQTT_H__
#define __C_MQTT_FORWARDER_MQTT_H__

#include <mosquitto.h>

void *mqtt_connect(void *);
void mqtt_connect_handler(struct mosquitto *, void *, int);
void mqtt_subscribe_handler(struct mosquitto *, void *, int, int, const int *);
void mqtt_disconnect_handler(struct mosquitto *, void *, int);
void mqtt_message_handler(struct mosquitto *, void *, const struct mosquitto_message *);

#endif
