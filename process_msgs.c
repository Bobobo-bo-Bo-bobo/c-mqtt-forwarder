#include "c-mqtt-forwarder.h"
#include "log.h"

#include <pthread.h>
#include <mosquitto.h>
#include <utlist.h>

unsigned int message_queue_length(struct mqtt_configuration *mcfg) {
    unsigned int count = 0;
    struct message *msg;

    pthread_mutex_lock(&msg_mutex);
    DL_FOREACH(mcfg->message_queue, msg) {
        count ++;
    }
    pthread_mutex_unlock(&msg_mutex);

    return count;
};

void destroy_msg(struct message *m) {
    if (m == NULL) {
        return;
    }

    if (m->data != NULL) {
        free(m->data);
        m->datalen = 0;
    }
};

void process_message_queue(struct mqtt_configuration *mcfg) {
    struct message *msg;
    struct message *tmp;
    int rc;

    pthread_mutex_lock(&msg_mutex);
    DL_FOREACH_SAFE(mcfg->message_queue, msg, tmp) {
        if (mcfg->config->loglevel == BE_VERBOSE) {
            pthread_mutex_lock(&log_mutex);
            LOG_INFO("Forwarding message to %s on %s:%d", mcfg->topic, mcfg->host, mcfg->port);
            pthread_mutex_unlock(&log_mutex);
        }

        rc = mosquitto_publish(mcfg->handle, NULL, mcfg->topic, msg->datalen, msg->data, mcfg->qos, false);
        if (rc != MOSQ_ERR_SUCCESS && mcfg->config->loglevel != BE_QUIET) {
            pthread_mutex_lock(&log_mutex);
            // XXX: Error or warning ?
            LOG_WARN("Can't publish message to %s on %s:%d: %s", mcfg->topic, mcfg->host, mcfg->port, mosquitto_strerror(rc));
            pthread_mutex_unlock(&log_mutex);
        }

#ifdef DEBUG
        pthread_mutex_lock(&log_mutex);
        LOG_DEBUG("%s:%d/%s: %s - %s", mcfg->host, mcfg->port, msg->data, mcfg->topic, mosquitto_strerror(rc));
        pthread_mutex_unlock(&log_mutex);
#endif

        switch (rc) {
            case MOSQ_ERR_SUCCESS:{
                                      DL_DELETE(mcfg->message_queue, msg);
                                      destroy_msg(msg);
                                      free(msg);

                                      if (mcfg->config->loglevel == BE_VERBOSE) {
                                          pthread_mutex_lock(&log_mutex);
                                          LOG_INFO("Message sent to %s on %s:%d and removed from queue", mcfg->topic, mcfg->host, mcfg->port);
                                          pthread_mutex_unlock(&log_mutex);
                                      }
                                      break;
                                  }

            case MOSQ_ERR_NOMEM:
            case MOSQ_ERR_NO_CONN:
            case MOSQ_ERR_PROTOCOL: {
                                        if (mcfg->config->loglevel != BE_QUIET) {
                                            pthread_mutex_lock(&log_mutex);
                                            LOG_WARN("Requeueing message to %s on %s:%d", mcfg->topic, mcfg->host, mcfg->port);
                                            pthread_mutex_unlock(&log_mutex);
                                        }
                                        break;
                                    }

            // always discard message on unrecoverable errors
            case MOSQ_ERR_INVAL:
            case MOSQ_ERR_PAYLOAD_SIZE:
            case MOSQ_ERR_MALFORMED_UTF8: {
                                              pthread_mutex_lock(&log_mutex);
                                              LOG_ERROR("Discarding invalid or malformed message to %s on %s:%d", mcfg->topic, mcfg->host, mcfg->port);
                                              pthread_mutex_unlock(&log_mutex);
                                              DL_DELETE(mcfg->message_queue, msg);
                                              destroy_msg(msg);
                                              free(msg);
                                              break;
                                          }

        };
    }
    pthread_mutex_unlock(&msg_mutex);
};

