#ifndef RELOAD_THREAD_H
#define RELOAD_THREAD_H

#include <pthread.h>
#include <syslog.h>
#include <unistd.h>

#include "debug.h"
#include "conf.h"
#include "fw_iptables.h"

extern char hupsignal;

void thread_reload ( void* arg );

#endif
