#include "c-mqtt-forwarder.h"
#include "usage.h"
#include "log.h"
#include "parse_cfg.h"
#include "mqtt.h"

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <mosquitto.h>
#include <utlist.h>

const char *short_options = "c:qvh";
static struct option long_options[] = {
    { "config", required_argument, 0, 'c' },
    { "help", no_argument, 0, 'h' },
    { "quiet", no_argument, 0, 'h' },
    { "verbose", no_argument, 0, 'v' },
    { NULL, 0, 0, 0 },
};

pthread_mutex_t log_mutex;

int main(int argc, char **argv) {
    struct configuration *cfg;
    char *config_file = NULL;
    int gorc;
    int optind = 0;
    short loglvl = 0;
    pthread_t *threads;
    int i;
    int rc;
    struct mqtt_configuration *m;

    while ((gorc = getopt_long(argc, argv, short_options, long_options, &optind)) != -1) {
        switch (gorc) {
            case 'h': {
                        usage();
                        return 0;
                    }
            case 'c': {
                        if (config_file != NULL) {
                            free(config_file);
                        }
                        config_file = strdup(optarg);
                        assert(config_file != NULL);
                        break;
                    }
            case 'q': {
                        loglvl = BE_QUIET;
                        break;
                    }
            case 'v': {
                        loglvl = BE_VERBOSE;
                        break;
                    }
            default: {
                        LOG_ERROR("Unknown command line argument\n");
                        usage();
                        return 1;
                    }
        }
    }

    if (config_file == NULL) {
        config_file = strdup(DEFAULT_CONFIGURATION_FILE);
        assert(config_file != NULL);
    }

    if (loglvl == BE_VERBOSE) {
        LOG_INFO("Parsing configuration from %s", config_file);
    }

    cfg = parse_config_file(config_file);
    if (cfg == NULL) {
        return 1;
    }

    cfg->loglevel = loglvl;

#ifdef DEBUG
    dump_configuration(cfg);
#endif

    if (cfg->loglevel == BE_VERBOSE) {
        LOG_INFO("Validating configuration");
    }

    if (!validate_configuration(cfg)) {
        LOG_ERROR("Invalid configuration");
        if (cfg->loglevel == BE_VERBOSE) {
            LOG_INFO("Destroying configuration");
        }
        destroy_configuration(cfg);
        return 1;
    }

    threads = (pthread_t *) calloc(cfg->count_in + cfg->count_out, sizeof(pthread_t));
    assert(threads != NULL);

    mosquitto_lib_init();

    i = 0;
    DL_FOREACH(cfg->fan_in, m) {
        if (cfg->loglevel == BE_VERBOSE) {
            pthread_mutex_lock(&log_mutex);
            LOG_INFO("Starting MQTT thread for %s:%d (topic %s)", m->host, m->port, m->topic);
            pthread_mutex_unlock(&log_mutex);
        }

        rc = pthread_create(&threads[i], NULL, mqtt_connect, (void *) m);
        if (rc != 0) {
            pthread_mutex_lock(&log_mutex);
            LOG_ERROR("Can't create new thread: %s", strerror(errno));
            pthread_mutex_unlock(&log_mutex);
            goto done;
        }
        i++;
    }

    DL_FOREACH(cfg->fan_out, m) {
        if (cfg->loglevel == BE_VERBOSE) {
            pthread_mutex_lock(&log_mutex);
            LOG_INFO("Starting MQTT thread for %s:%d (topic %s)", m->host, m->port, m->topic);
            pthread_mutex_unlock(&log_mutex);
        }

        rc = pthread_create(&threads[i], NULL, mqtt_connect, (void *) m);
        if (rc != 0) {
            pthread_mutex_lock(&log_mutex);
            LOG_ERROR("Can't create new thread: %s", strerror(errno));
            pthread_mutex_unlock(&log_mutex);
            goto done;
        }
        i++;
    }

    for (i = 0; i< cfg->count_in + cfg->count_out; i++) {
        pthread_join(threads[i], NULL);
    }

done:
    mosquitto_lib_cleanup();
    if (cfg->loglevel == BE_VERBOSE) {
        LOG_INFO("Destroying configuration");
    }

    destroy_configuration(cfg);
}

