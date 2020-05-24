#include "c-mqtt-forwarder.h"
#include "usage.h"

#include <mosquitto.h>
#include <stdio.h>

const char *usage_string = "%s version %s\n"
"Copyright (C) by Andreas Maus <maus@ypbind.de>\n"
"This program comes with ABSOLUTELY NO WARRANTY.\n"
"\n"
"%s is distributed under the Terms of the GNU General\n"
"Public License Version 3. (http://www.gnu.org/copyleft/gpl.html)\n"
"\n"
"Using libmosquitto version: %d.%d.%d\n"
"\n"
"Usage: %s [-c <cfg>|--config=<cfg>] [-h|--help] [-q|--quiet] [-v|--verbose]\n"
"\n"
"  -c <cfg>         Read configuration from <cfg>\n"
"  --config=<cfg>   Default: %s\n"
"\n"
"  -h               This text\n"
"  --help\n"
"\n"
"  -q               Quiet operation\n"
"  --quiet\n"
"\n"
"  -v               Verbose operation\n"
"  --verbose\n"
"\n";

void usage() {
    int major;
    int minor;
    int micro;

    mosquitto_lib_version(&major, &minor, &micro);
    printf(usage_string, C_MQTT_FORWARDER_NAME, C_MQTT_FORWARDER_VERSION, C_MQTT_FORWARDER_NAME, major, minor, micro, C_MQTT_FORWARDER_NAME, DEFAULT_CONFIGURATION_FILE);
}

