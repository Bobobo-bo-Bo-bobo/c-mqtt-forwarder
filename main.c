#include "c-mqtt-forwarder.h"
#include "usage.h"
#include "log.h"
#include "parse_cfg.h"

#include <assert.h>
#include <getopt.h>
#include <string.h>

const char *short_options = "c:qvh";
static struct option long_options[] = {
    { "config", required_argument, 0, 'c' },
    { "quiet", no_argument, 0, 'h' },
    { "verbose", no_argument, 0, 'v' },
    { NULL, 0, 0, 0 },
};

int main(int argc, char **argv) {
    struct configuration *cfg;
    char *config_file = NULL;
    int gorc;
    int optind = 0;
    short loglvl = 0;

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
                        log_error("Unknown command line argument\n");
                        usage();
                        return 1;
                    }
        }
    }

    if (config_file == NULL) {
        config_file = strdup(DEFAULT_CONFIGURATION_FILE);
        assert(config_file != NULL);
    }

    cfg = parse_config_file(config_file);
    if (cfg == NULL) {
        return 1;
    }

#ifdef DEBUG
    dump_configuration(cfg);
#endif

    destroy_configuration(cfg);
}

