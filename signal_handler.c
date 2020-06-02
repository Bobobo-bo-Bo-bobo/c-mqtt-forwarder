#include "c-mqtt-forwarder.h"
#include "signal_handler.h"

#include <signal.h>

void block_signal(void) {
    sigset_t smask;
    sigemptyset(&smask);
    sigaddset(&smask, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &smask, NULL);
}

