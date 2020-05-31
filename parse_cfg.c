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
#include "util.h"
#include "parse_cfg.h"

#include <cjson/cJSON.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <utlist.h>

#ifdef DEBUG
#include <stdio.h>
#endif

void set_mqtt_configuration_defaults(struct mqtt_configuration *mqttcfg) {
    if (mqttcfg == NULL) {
        return;
    }

    mqttcfg->port = DEFAULT_MQTT_PORT;
    mqttcfg->qos = 0;
    mqttcfg->timeout = DEFAULT_MQTT_TIMEOUT;
    mqttcfg->keepalive = DEFAULT_MQTT_KEEPALIVE;
    mqttcfg->reconnect_delay = DEFAULT_MQTT_RECONNECT_DELAY;
    mqttcfg->insecure_ssl = false;
}

char *read_configuration_file(const char *cfg_file) {
    char *buffer = NULL;
    int rc;
    int fd;
    struct stat sbuf;
    ssize_t rcnt;

    if (cfg_file == NULL) {
        return NULL;
    }

    rc = stat(cfg_file, &sbuf);
    if (rc == -1) {
        LOG_FATAL("Can't get file status of %s: %s", cfg_file, strerror(errno));
        return NULL;
    }

    buffer = calloc(1, sbuf.st_size + 1);
    if (buffer == NULL) {
        LOG_FATAL("Unable to allocate %d bytes from memory", sbuf.st_size + 1);
        return NULL;
    }

    fd = open(cfg_file, O_RDONLY);
    if (fd == -1) {
        LOG_FATAL("Can't open configuration file %s for reading: %s", cfg_file, strerror(errno));
        return NULL;
    }

    // XXX: read _CAN_ return fewer bytes (see man 2 read) but at the moment we ignore this particular case
    // XXX: we also assume file size is < SSIZE_MAX (2,147,479,552 bytes on Linux)
    rcnt = read(fd, buffer, sbuf.st_size);
    if (rcnt == -1) {
        LOG_FATAL("Reading from configuration file %s failed: %s", cfg_file, strerror(errno));
        return NULL;
    }

    rc = close(fd);
    if (rc == -1) {
        LOG_FATAL("An error occured while closing %s: %s", cfg_file, strerror(errno));
        return NULL;
    }

    return buffer;
}

struct mqtt_configuration *parse_mqtt_configuration(const cJSON *mcfg) {
    struct mqtt_configuration *mqttcfg;
    const cJSON *c;

    mqttcfg = calloc(1, sizeof(struct mqtt_configuration));
    if (mqttcfg == NULL) {
        LOG_FATAL("Unable to allocate %d bytes from memory", sizeof(struct configuration));
        return NULL;
    }
    set_mqtt_configuration_defaults(mqttcfg);

    c = cJSON_GetObjectItemCaseSensitive(mcfg, "host");
    if (cJSON_IsString(c) && (c->valuestring != NULL)) {
        mqttcfg->host = strdup(c->valuestring);
        assert(mqttcfg->host != NULL);
    }

    c = cJSON_GetObjectItemCaseSensitive(mcfg, "port");
    if (cJSON_IsNumber(c)) {
        if ((c->valueint <= 0) || (c->valueint > 65535)) {
            LOG_ERROR("Invalid port number %d", c->valueint);
            return NULL;
        }
        mqttcfg->port = c->valueint;
    }

    c = cJSON_GetObjectItemCaseSensitive(mcfg, "topic");
    if (cJSON_IsString(c) && (c->valuestring != NULL)) {
        mqttcfg->topic = strdup(c->valuestring);
        assert(mqttcfg->topic != NULL);
    }

    c = cJSON_GetObjectItemCaseSensitive(mcfg, "insecure_ssl");
    if (cJSON_IsBool(c)) {
        if (cJSON_IsTrue(c)) {
            mqttcfg->insecure_ssl = true;
        }

        if (cJSON_IsFalse(c)) {
            mqttcfg->insecure_ssl = false;
        }
    }

    c = cJSON_GetObjectItemCaseSensitive(mcfg, "ca_file");
    if ((cJSON_IsString(c)) && (c->valuestring != NULL)) {
        mqttcfg->ca_file = strdup(c->valuestring);
        assert(mqttcfg->ca_file != NULL);
    }

    c = cJSON_GetObjectItemCaseSensitive(mcfg, "user");
    if ((cJSON_IsString(c)) && (c->valuestring)) {
        mqttcfg->user = strdup(c->valuestring);
        assert(mqttcfg->user);
    }

    c = cJSON_GetObjectItemCaseSensitive(mcfg, "password");
    if ((cJSON_IsString(c)) && (c->valuestring)) {
        mqttcfg->password = strdup(c->valuestring);
        assert(mqttcfg->password);
    }

    c = cJSON_GetObjectItemCaseSensitive(mcfg, "ssl_auth_public");
    if ((cJSON_IsString(c)) && (c->valuestring)) {
        mqttcfg->ssl_auth_public = strdup(c->valuestring);
        assert(mqttcfg->ssl_auth_public);
    }

    c = cJSON_GetObjectItemCaseSensitive(mcfg, "ssl_auth_private");
    if ((cJSON_IsString(c)) && (c->valuestring)) {
        mqttcfg->ssl_auth_private = strdup(c->valuestring);
        assert(mqttcfg->ssl_auth_private);
    }

    c = cJSON_GetObjectItemCaseSensitive(mcfg, "qos");
    if (cJSON_IsNumber(c)) {
        if ((c->valueint < 0) && (c->valueint > 2)) {
            LOG_ERROR("Invalid QoS value %d\n", c->valueint);
            return NULL;
        }
        mqttcfg->qos = c->valueint;
    }

    c = cJSON_GetObjectItemCaseSensitive(mcfg, "timeout");
    if (cJSON_IsNumber(c)) {
        if (c->valueint <= 0) {
            LOG_ERROR("Invalid timeout %d", c->valueint);
            return NULL;
        }
        mqttcfg->timeout = c->valueint;
    }

    c = cJSON_GetObjectItemCaseSensitive(mcfg, "keepalive");
    if (cJSON_IsNumber(c)) {
        if (c->valueint <= 0) {
            LOG_ERROR("Invalid keepalive %d", c->valueint);
            return NULL;
        }
        mqttcfg->keepalive = c->valueint;
    }

    c = cJSON_GetObjectItemCaseSensitive(mcfg, "reconnect_delay");
    if (cJSON_IsNumber(c)) {
        if (c->valueint <= 0) {
            LOG_ERROR("Invalid reconnect_delay value %d", c->valueint);
            return NULL;
        }
        mqttcfg->reconnect_delay = c->valueint;
    }
    return mqttcfg;
}

void destroy_mqtt_configuration(struct mqtt_configuration *mqttcfg) {
    struct message *msg;

    if (mqttcfg == NULL) {
        return;
    }

    if (mqttcfg->host != NULL) {
        free(mqttcfg->host);
    }
    if (mqttcfg->user) {
        free(mqttcfg->user);
    }
    if (mqttcfg->password) {
        free(mqttcfg->password);
    }
    if (mqttcfg->ssl_auth_public) {
        free(mqttcfg->ssl_auth_public);
    }
    if (mqttcfg->ssl_auth_private) {
        free(mqttcfg->ssl_auth_private);
    }
    if (mqttcfg->ca_file) {
        free(mqttcfg->ca_file);
    }
    if (mqttcfg->topic) {
        free(mqttcfg->topic);
    }

    DL_FOREACH(mqttcfg->message_queue, msg) {
        if (msg != NULL) {
            if (msg->data != NULL) {
                free(msg->data);
            }
            free(msg);
        }
    }
    free(mqttcfg);
}

void destroy_configuration(struct configuration *cfg) {
    struct mqtt_configuration *element;
    struct mqtt_configuration *temp;

    if (cfg == NULL) {
        return;
    }

    if (cfg->fan_in != NULL) {
        DL_FOREACH_SAFE(cfg->fan_in, element, temp) {
            DL_DELETE(cfg->fan_in, element);
            destroy_mqtt_configuration(element);
        }
    }

    if (cfg->fan_out != NULL) {
        DL_FOREACH_SAFE(cfg->fan_out, element, temp) {
            DL_DELETE(cfg->fan_out, element);
            destroy_mqtt_configuration(element);
        }
    }
}

struct configuration *parse_config_file(const char *cfg_file) {
    struct configuration *cfg = NULL;
    char *buffer = NULL;
    cJSON *parser;
    const cJSON *inlist;
    const cJSON *outlist;
    const cJSON *incfg;
    const cJSON *outcfg;
    const char *parse_err;
    struct mqtt_configuration *mqttcfg;

    if (cfg_file == NULL) {
        return NULL;
    }

    cfg = calloc(1, sizeof(struct configuration));
    if (cfg == NULL) {
        LOG_FATAL("Unable to allocate %d bytes from memory", sizeof(struct configuration));
        return NULL;
    }

    buffer = read_configuration_file(cfg_file);
    if (buffer == NULL) {
        destroy_configuration(cfg);
        free(cfg);
        cfg = NULL;
        goto done;
    }

    parser = cJSON_Parse(buffer);
    if (parser == NULL) {
        parse_err = cJSON_GetErrorPtr();
        if (parse_err != NULL) {
            LOG_ERROR("Can't parse JSON configuration: %s", parse_err);
            destroy_configuration(cfg);
            free(cfg);
            cfg = NULL;
            goto done;
        }
        LOG_ERROR("Can't parse JSON configuration");
        destroy_configuration(cfg);
        free(cfg);
        cfg = NULL;
        goto done;
    }

    inlist = cJSON_GetObjectItemCaseSensitive(parser, "in");
    cJSON_ArrayForEach(incfg, inlist) {
        mqttcfg = parse_mqtt_configuration(incfg);
        if (mqttcfg == NULL) {
            destroy_configuration(cfg);
            free(cfg);
            cfg = NULL;
            goto done;
        }
        mqttcfg->direction = DIRECTION_IN;
        mqttcfg->config = cfg;
        DL_APPEND(cfg->fan_in, mqttcfg);
        cfg->count_in ++;
    }

    outlist = cJSON_GetObjectItemCaseSensitive(parser, "out");
    cJSON_ArrayForEach(outcfg, outlist) {
        mqttcfg = parse_mqtt_configuration(outcfg);
        if (mqttcfg == NULL) {
            destroy_configuration(cfg);
            free(cfg);
            cfg = NULL;
            goto done;
        }
        mqttcfg->direction = DIRECTION_OUT;
        mqttcfg->config = cfg;
        DL_APPEND(cfg->fan_out, mqttcfg);
        cfg->count_out ++;
    }

done:
    cJSON_Delete(parser);
    return cfg;
}

#ifdef DEBUG
void dump_mqtt_configuration(const struct mqtt_configuration *mcfg) {
    printf(">>> host: %s\n", mcfg->host);
    printf(">>> port: %d\n", mcfg->port);
    printf(">>> user: %s\n", mcfg->user);
    printf(">>> password: %s\n", mcfg->password);
    printf(">>> ssl_auth_public: %s\n", mcfg->ssl_auth_public);
    printf(">>> ssl_auth_private: %s\n", mcfg->ssl_auth_private);
    printf(">>> ca_file: %s\n", mcfg->ca_file);
    printf(">>> insecure_ssl: %d\n", mcfg->insecure_ssl);
    printf(">>> qos: %d\n", mcfg->qos);
    printf(">>> topic: %s\n", mcfg->topic);
    printf(">>> timeout: %d\n", mcfg->timeout);
    printf(">>> reconnect_delay: %d\n", mcfg->reconnect_delay);
    printf(">>> keepalive: %d\n", mcfg->keepalive);
    printf(">>> direction: %d\n", mcfg->direction);
    printf(">>> message_queue: 0x%0x\n", mcfg->message_queue);
    printf("---\n");
}

void dump_configuration(const struct configuration *cfg) {
    struct mqtt_configuration *mcfg;

    printf("cfg->loglevel: %d\n", cfg->loglevel);
    printf("cfg->count_in: %d\n", cfg->count_in);
    printf("cfg->count_out: %d\n", cfg->count_out);
    printf("cfg->fan_in: 0x%0x\n", cfg->fan_in);
    DL_FOREACH(cfg->fan_in, mcfg) {
        dump_mqtt_configuration(mcfg);
    }

    printf("cfg->fan_out: 0x%0x\n", cfg->fan_out);
    DL_FOREACH(cfg->fan_out, mcfg) {
        dump_mqtt_configuration(mcfg);
    }
}
#endif

bool validate_mqtt_configuration(const struct mqtt_configuration *mcfg) {
    if ((mcfg->host == NULL) || (strlen(mcfg->host) == 0)) {
        LOG_ERROR("Missing MQTT host");
        return false;
    }

    if ((mcfg->topic == NULL) || (strlen(mcfg->topic) == 0)) {
        LOG_ERROR("Missing MQTT topic");
        return false;
    }

    if (mcfg->direction == DIRECTION_OUT) {
        // outgoing topic should not end in a wildcard (0x23 - '#' / 0x2b - '+')
        if ((index(mcfg->topic, 0x23) != NULL) || (index(mcfg->topic, 0x2b) != NULL)) {
            LOG_ERROR("Topic for outgoing broker should not contain a wildcard");
            return false;
        }
    }

    if (mcfg->topic[0] == '/') {
        LOG_ERROR("Topic can't start with a slash");
        return false;
    }

    if (mcfg->topic[strlen(mcfg->topic)] == '/') {
        LOG_ERROR("Topic can't end with a slash");
        return false;
    }

    if ((mcfg->user == NULL) && (mcfg->password == NULL) && (mcfg->ssl_auth_public == NULL) && (mcfg->ssl_auth_private == NULL)) {
        LOG_ERROR("No authentication method (user/password or SSL client certificate) found");
        return false;
    }

    if ((mcfg->user != NULL) && (mcfg->password == NULL)) {
        LOG_ERROR("No password found for user/password authentication for user %s", mcfg->user);
        return false;
    }

    if ((mcfg->user == NULL) && (mcfg->password != NULL)) {
        LOG_ERROR("No user found for user/password authentication");
        return false;
    }


    return true;
}

bool validate_configuration(const struct configuration *cfg) {
    struct mqtt_configuration *mcfg;

    if (cfg->fan_in == NULL) {
        LOG_ERROR("No input broker found");
        return false;
    }

    if (cfg->count_in == 0) {
        LOG_ERROR("No input brokers");
        return false;
    }

    if (cfg->count_out == 0) {
        LOG_ERROR("No output brokers");
        return false;
    }

    DL_FOREACH(cfg->fan_in, mcfg) {
        if (!validate_mqtt_configuration(mcfg)) {
            return false;
        }
    }

    if (cfg->fan_out == NULL) {
        LOG_ERROR("No output broker found");
        return false;
    }

    DL_FOREACH(cfg->fan_out, mcfg) {
        if (!validate_mqtt_configuration(mcfg)) {
            return false;
        }
    }

    return true;
}

