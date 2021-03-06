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
#include "log/log.h"
#include "mqtt.h"
#include "util.h"
#include "process_msgs.h"
#include "signal_handler.h"

#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <mosquitto.h>
#include <utlist.h>
#include <unistd.h>
#include <pthread.h>

void mqtt_message_handler(struct mosquitto *mqtt, void *ptr, const struct mosquitto_message *msg) {
    struct mqtt_configuration *mcfg = (struct mqtt_configuration *) ptr;
    struct mqtt_configuration *fan;
    struct message *mmsg;

    if (mcfg->config->loglevel == BE_VERBOSE) {
        pthread_mutex_lock(&log_mutex);
        LOG_INFO("Received %d bytes of message on %s from %s:%d", msg->payloadlen, msg->topic, mcfg->host, mcfg->port);
        pthread_mutex_unlock(&log_mutex);
    }

    // loop over outgoing brokers
    pthread_mutex_lock(&fan_mutex);
    DL_FOREACH(mcfg->config->fan_out, fan) {
        // make a copy of the message and enqueue message for all outgoing
        mmsg = calloc(1, sizeof(struct message));
        assert(mmsg != NULL);

        mmsg->data = calloc(1, msg->payloadlen);
        if (mmsg->data == NULL) {
            pthread_mutex_lock(&log_mutex);
            LOG_ERROR("Allocation of %d bytes of memory for message copy failed, discarding message", msg->payloadlen);
            pthread_mutex_unlock(&log_mutex);
            free(mmsg);
            // XXX: Should we all other outgoing brokers? It's unlikely the allocation will succeed.
            continue;
        }

        mmsg->datalen = msg->payloadlen;
        memcpy(mmsg->data, msg->payload, msg->payloadlen);

        mmsg->topic = calloc(1, strlen(fan->topic) + strlen(msg->topic) + 2);
        if (mmsg->topic == NULL) {
            pthread_mutex_lock(&log_mutex);
            LOG_ERROR("Allocation of %d bytes of memory for new topic failed, discarding message", strlen(fan->topic) + strlen(msg->topic) + 2);
            pthread_mutex_unlock(&log_mutex);
            free(mmsg->data);
            free(mmsg);
            // XXX: Should we all other outgoing brokers? It's unlikely the allocation will succeed.
            continue;
        }

        memcpy(mmsg->topic, fan->topic, strlen(fan->topic));
        mmsg->topic[strlen(fan->topic)] = '/';
        memcpy(mmsg->topic + strlen(fan->topic) + 1, msg->topic, strlen(msg->topic));

        pthread_mutex_lock(&msg_mutex);
        DL_APPEND(fan->message_queue, mmsg);
        pthread_mutex_unlock(&msg_mutex);

    };
    pthread_mutex_unlock(&fan_mutex);

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
        LOG_ERROR("%s", mosquitto_strerror(result));
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
    int _rc;

    if (rc != MOSQ_ERR_SUCCESS) {
        pthread_mutex_lock(&log_mutex);
        LOG_ERROR("Unexpected disconnect from %s:%d: %s ... retrying in %d seconds", mcfg->host, mcfg->port, mosquitto_strerror(rc), mcfg->reconnect_delay);
        pthread_mutex_unlock(&log_mutex);
        sleep(mcfg->reconnect_delay);

        // XXX: Is it wise to block disconnect handler?
        do {
            pthread_mutex_lock(&log_mutex);
            LOG_INFO("Reconnecting to %s:%d", mcfg->host, mcfg->port);
            pthread_mutex_unlock(&log_mutex);

            _rc = mosquitto_connect(mqtt, mcfg->host, mcfg->port, mcfg->keepalive);
            if (_rc != MOSQ_ERR_SUCCESS) {
                pthread_mutex_lock(&log_mutex);
                LOG_ERROR("Can't connect to %s:%d: %s ... retrying in %d seconds\n", mcfg->host, mcfg->port, mosquitto_strerror(rc), mcfg->reconnect_delay);
                pthread_mutex_unlock(&log_mutex);
                sleep(mcfg->reconnect_delay);
            }
        } while (_rc != MOSQ_ERR_SUCCESS);
    } else {
        pthread_mutex_lock(&log_mutex);
        LOG_INFO("Disconnecting from %s:%d", mcfg->host, mcfg->port);
        pthread_mutex_unlock(&log_mutex);

        mosquitto_loop_stop(mqtt, true);
    }
};

void *mqtt_connect(void *ptr) {
    struct mqtt_configuration *mcfg = (struct mqtt_configuration *) ptr;
    struct mosquitto *mqtt;
    char *mqtt_client_id;
    int rc;

    block_signal();

    rc = pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    if (rc != 0) {
        LOG_FATAL("Unable to set cancellatio state for thread");
        abort();
    }

    rc = pthread_setcancelstate(PTHREAD_CANCEL_DEFERRED, NULL);
    if (rc != 0) {
        LOG_FATAL("Unable to set cancellatio state for thread");
        abort();
    }

    mqtt_client_id = uuidgen();

    mqtt = mosquitto_new(mqtt_client_id, true, ptr);
    assert(mqtt != NULL);

    // each MQTT thread uses it's own handle, no mutex required
    mcfg->handle = mqtt;

    mosquitto_threaded_set(mqtt, true);

    if (mcfg->use_tls) {
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
        if (mcfg->use_tls) {
            rc = mosquitto_tls_set(mqtt, mcfg->ca_file, mcfg->ca_dir, NULL, NULL, NULL);
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
        rc = mosquitto_tls_set(mqtt, mcfg->ca_file, mcfg->ca_dir, mcfg->ssl_auth_public, mcfg->ssl_auth_private, NULL);
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

    do {
        pthread_mutex_lock(&log_mutex);
        LOG_INFO("Connecting to %s:%d", mcfg->host, mcfg->port);
        pthread_mutex_unlock(&log_mutex);

        rc = mosquitto_connect(mqtt, mcfg->host, mcfg->port, mcfg->keepalive);

        if (errno == EINTR) {
            mosquitto_disconnect(mqtt);
            mosquitto_loop_stop(mqtt, true);
            return NULL;
        }

        if (rc != MOSQ_ERR_SUCCESS) {
            pthread_mutex_lock(&log_mutex);
            LOG_ERROR("Can't connect to %s:%d: %s ... retrying in %d seconds\n", mcfg->host, mcfg->port, mosquitto_strerror(rc), mcfg->reconnect_delay);
            pthread_mutex_unlock(&log_mutex);
            sleep(mcfg->reconnect_delay);
        }
    } while (rc != MOSQ_ERR_SUCCESS);

    if (mcfg->direction == DIRECTION_IN) {
        do {
            pthread_mutex_lock(&log_mutex);
            LOG_INFO("Starting connection loop for %s:%d", mcfg->host, mcfg->port);
            pthread_mutex_unlock(&log_mutex);

            rc = mosquitto_loop_forever(mqtt, 1000 * mcfg->timeout, 1);
            if (rc != MOSQ_ERR_SUCCESS) {
                pthread_mutex_lock(&log_mutex);
                LOG_ERROR("MQTT loop_forever failed for %s:%d: %s ... retrying in %d seconds\n", mcfg->host, mcfg->port, mosquitto_strerror(rc), mcfg->reconnect_delay);
                pthread_mutex_unlock(&log_mutex);
                sleep(mcfg->reconnect_delay);
            }
        } while (rc != MOSQ_ERR_SUCCESS);
    } else {
        for (;;) {

#ifdef DEBUG
            pthread_mutex_lock(&log_mutex);
            LOG_DEBUG("Triggering connection loop for %s:%d", mcfg->host, mcfg->port);
            pthread_mutex_unlock(&log_mutex);
#endif

            rc = mosquitto_loop(mqtt, 1000 * mcfg->timeout, 1);

            if (errno == EINTR) {
                mosquitto_disconnect(mqtt);
                mosquitto_loop_stop(mqtt, true);
                return NULL;
            }

#ifdef DEBUG
            pthread_mutex_lock(&log_mutex);
            LOG_DEBUG("mosquitto_loop for %s:%d returned %s", mcfg->host, mcfg->port, strerror(rc));
            pthread_mutex_unlock(&log_mutex);
#endif

            if (rc != MOSQ_ERR_SUCCESS) {
                pthread_mutex_lock(&log_mutex);
                LOG_ERROR("MQTT loop failed for %s:%d: %s ... retrying in %d seconds", mcfg->host, mcfg->port, mosquitto_strerror(rc), mcfg->reconnect_delay);
                pthread_mutex_unlock(&log_mutex);
                sleep(mcfg->reconnect_delay);
                // mosquitto_loop_forever handles reconnects but mosquitto_loop does not
                // Note: We don't care about the return code here. mosquitto_loop will fail if reconnect failed
                mosquitto_reconnect(mqtt);
            } else {
                process_message_queue(mcfg);
            }
        }
    }
};

