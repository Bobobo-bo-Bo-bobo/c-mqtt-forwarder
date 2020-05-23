#include "c-mqtt-forwarder.h"
#include "log.h"
#include "mqtt.h"
#include "util.h"
#include "process_msgs.h"

#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <mosquitto.h>

void mqtt_message_handler(struct mosquitto *mqtt, void *ptr, const struct mosquitto_message *msg) {
    struct mqtt_configuration *mcfg = (struct mqtt_configuration *) ptr;

    if (mcfg->config->loglevel == BE_VERBOSE) {
        pthread_mutex_lock(&log_mutex);
        LOG_INFO("Received %d bytes of message on %s from %s:%d", msg->payloadlen, msg->topic, mcfg->host, mcfg->port);
        pthread_mutex_unlock(&log_mutex);
    }
};

void mqtt_connect_handler(struct mosquitto *mqtt, void *ptr, int result) {
    struct mqtt_configuration *mcfg = (struct mqtt_configuration *) ptr;
    int rc;

    if (mcfg->config->loglevel == BE_VERBOSE) {
        pthread_mutex_lock(&log_mutex);
        LOG_INFO("Connecting to %s:%d", mcfg->host, mcfg->port);
        pthread_mutex_unlock(&log_mutex);
    }

    if (result != MOSQ_ERR_SUCCESS) {
        pthread_mutex_lock(&log_mutex);
        LOG_ERROR("%s", mosquitto_strerror(rc));
        pthread_mutex_unlock(&log_mutex);
        return;
    }

    if (mcfg->config->loglevel == BE_VERBOSE) {
        pthread_mutex_lock(&log_mutex);
        LOG_INFO("Subscribing to topic %s on %s:%d", mcfg->topic, mcfg->host, mcfg->port);
        pthread_mutex_unlock(&log_mutex);
    }

    rc = mosquitto_subscribe(mqtt, NULL, mcfg->topic, mcfg->qos);
    if (rc != MOSQ_ERR_SUCCESS) {
        pthread_mutex_lock(&log_mutex);
        LOG_ERROR("Can't subscribe to topic %s on %s:%d with QoS %d: %s", mcfg->topic, mcfg->host, mcfg->port, mcfg->qos, mosquitto_strerror(rc));
        pthread_mutex_unlock(&log_mutex);
        return;
    }
};

void mqtt_subscribe_handler(struct mosquitto *mqtt, void *ptr, int mid, int qos_count, const int *granted_qos) {
    struct mqtt_configuration *mcfg = (struct mqtt_configuration *) ptr;

    if (mcfg->config->loglevel == BE_VERBOSE) {
        pthread_mutex_lock(&log_mutex);
        LOG_INFO("Subscribed to %s on %s:%d", mcfg->topic, mcfg->host, mcfg->port);
        pthread_mutex_unlock(&log_mutex);
    }
};

void mqtt_disconnect_handler(struct mosquitto *mqtt, void *ptr, int rc) {
    struct mqtt_configuration *mcfg = (struct mqtt_configuration *) ptr;

    if (rc != MOSQ_ERR_SUCCESS) {
        pthread_mutex_lock(&log_mutex);
        LOG_ERROR("Unexpected disconnect from %s:%d: %s", mcfg->host, mcfg->port, mosquitto_strerror(rc));
        pthread_mutex_unlock(&log_mutex);
    } else {
        pthread_mutex_lock(&log_mutex);
        LOG_INFO("Disconnecting from %s:%d", mcfg->host, mcfg->port);
        pthread_mutex_unlock(&log_mutex);
    }
};

void *mqtt_connect(void *ptr) {
    struct mqtt_configuration *mcfg = (struct mqtt_configuration *) ptr;
    struct mosquitto *mqtt;
    char *mqtt_client_id;
    int rc;

    mqtt_client_id = uuidgen();

    mqtt = mosquitto_new(mqtt_client_id, true, ptr);
    assert(mqtt != NULL);

    mosquitto_threaded_set(mqtt, true);

    if (mcfg->ca_file != NULL) {
        if (mcfg->insecure_ssl) {
            rc = mosquitto_tls_opts_set(mqtt, MQTT_SSL_VERIFY_NONE, NULL, NULL);
        } else {
            rc = mosquitto_tls_opts_set(mqtt, MQTT_SSL_VERIFY_PEER, NULL, NULL);
        }

        if (rc != MOSQ_ERR_SUCCESS) {
            pthread_mutex_lock(&log_mutex);
            LOG_ERROR("Can't initialise MQTT data structure: %s", mosquitto_strerror(rc));
            pthread_mutex_unlock(&log_mutex);
            abort();
        }
    }

    // Authenticate using user/password or client certificate
    // XXX: There is a third option, "pre-shared key over TLS" - mosquitto_tls_psk_set
    if (mcfg->user != NULL) {
        if (mcfg->ca_file != NULL) {
            rc = mosquitto_tls_set(mqtt, mcfg->ca_file, NULL, NULL, NULL, NULL);
            if (rc != MOSQ_ERR_SUCCESS) {
                pthread_mutex_lock(&log_mutex);
                LOG_ERROR("Can't initialise MQTT data structure for TLS: %s", mosquitto_strerror(rc));
                pthread_mutex_unlock(&log_mutex);
                abort();
            }
        }

        rc = mosquitto_username_pw_set(mqtt, mcfg->user, mcfg->password);
        if (rc != MOSQ_ERR_SUCCESS) {
            pthread_mutex_lock(&log_mutex);
            LOG_ERROR("Can't initialise MQTT data structure: %s", mosquitto_strerror(rc));
            pthread_mutex_unlock(&log_mutex);
            abort();
        }
    } else {
        rc = mosquitto_tls_set(mqtt, mcfg->ca_file, NULL, mcfg->ssl_auth_public, mcfg->ssl_auth_private, NULL);
        if (rc != MOSQ_ERR_SUCCESS) {
            pthread_mutex_lock(&log_mutex);
            LOG_ERROR("Can't initialise MQTT data structure: %s", mosquitto_strerror(rc));
            pthread_mutex_unlock(&log_mutex);
            abort();
        }
    }

    if (mcfg->config->loglevel == BE_VERBOSE) {
        pthread_mutex_lock(&log_mutex);
        LOG_INFO("Setting event handlers for %s:%d", mcfg->host, mcfg->port);
        pthread_mutex_unlock(&log_mutex);
    }

    mosquitto_connect_callback_set(mqtt, mqtt_connect_handler);
    mosquitto_subscribe_callback_set(mqtt, mqtt_subscribe_handler);
    mosquitto_disconnect_callback_set(mqtt, mqtt_disconnect_handler);

    if (mcfg->direction == DIRECTION_IN) {
        mosquitto_message_callback_set(mqtt, mqtt_message_handler);
    }

    rc = mosquitto_connect(mqtt, mcfg->host, mcfg->port, mcfg->keepalive);
    if (rc != MOSQ_ERR_SUCCESS) {
        pthread_mutex_lock(&log_mutex);
        LOG_ERROR("Can't connect to %s:%d: %s\n", mcfg->host, mcfg->port, mosquitto_strerror(rc));
        pthread_mutex_unlock(&log_mutex);
        // TODO: Don't fail. try to reconnect instead
        abort();
    }

    if (mcfg->direction == DIRECTION_IN) {
        rc = mosquitto_loop_forever(mqtt, mcfg->timeout, 1);
        if (rc != MOSQ_ERR_SUCCESS) {
            pthread_mutex_lock(&log_mutex);
            LOG_ERROR("MQTT loop_forever failed for %s:%d: %s\n", mcfg->host, mcfg->port, mosquitto_strerror(rc));
            pthread_mutex_unlock(&log_mutex);
            // TODO: Don't fail. try to reconnect instead
            abort();
        }
    } else {
        rc = MOSQ_ERR_SUCCESS;
        while (rc != MOSQ_ERR_SUCCESS) {
            process_message_queue(mcfg);

            rc = mosquitto_loop(mqtt, mcfg->timeout, 1);
            if (rc != MOSQ_ERR_SUCCESS) {
                pthread_mutex_lock(&log_mutex);
                LOG_ERROR("MQTT loop failed for %s:%d: %s\n", mcfg->host, mcfg->port, mosquitto_strerror(rc));
                pthread_mutex_unlock(&log_mutex);
            }
        }
    }
};

