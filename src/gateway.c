/* vim: set et sw=4 ts=4 sts=4 : */
/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free:Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
 \********************************************************************/

/** @internal
  @file gateway.c
  @brief Main loop
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@miniguru.ca>
 */

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <time.h>

/* for strerror() */
#include <string.h>

/* for wait() */
#include <sys/wait.h>

/* for unix socket communication*/
#include <sys/socket.h>
#include <sys/un.h>

#include "common.h"
#include "httpd.h"
#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "gateway.h"
#include "firewall.h"
#include "commandline.h"
#include "auth.h"
#include "http.h"
#include "client_list.h"
#include "ping_thread.h"
#include "httpd_thread.h"
#include "reload_thread.h"
#include "util.h"

/** XXX Ugly hack 
 * We need to remember the thread IDs of threads that simulate wait with pthread_cond_timedwait
 * so we can explicitly kill them in the termination handler
 */
static pthread_t tid_fw_counter = 0;
static pthread_t tid_ping = 0;
static pthread_t tid_reload = 0;

time_t started_time = 0;

/* The internal web server */
httpd * webserver = NULL;

/**@internal
 * @brief Handles SIGCHLD signals to avoid zombie processes
 *
 * When a child process exits, it causes a SIGCHLD to be sent to the
 * process. This handler catches it and reaps the child process so it
 * can exit. Otherwise we'd get zombie processes.
 */
void
sigchld_handler(int s)
{
    int status;
    pid_t rc;

    debug(LOG_DEBUG, "Handler for SIGCHLD called. Trying to reap a child");

    rc = waitpid(-1, &status, WNOHANG);

    debug(LOG_DEBUG, "Handler for SIGCHLD reaped child PID %d", rc);
}

/** Exits cleanly after cleaning up the firewall.  
 *  Use this function anytime you need to exit after firewall initialization.
 *  @param s Integer that is really a boolean, true means voluntary exit, 0 means error.
 */
void
termination_handler(int s)
{
    static pthread_mutex_t sigterm_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_t self = pthread_self();

    debug(LOG_INFO, "Handler for termination caught signal %d", s);

    /* Makes sure we only call fw_destroy() once. */
    if (pthread_mutex_trylock(&sigterm_mutex)) {
        debug(LOG_INFO, "Another thread already began global termination handler. I'm exiting");
        pthread_exit(NULL);
    } else {
        debug(LOG_INFO, "Cleaning up and exiting");
    }

    debug(LOG_INFO, "Flushing firewall rules...");
    fw_destroy();

    /* XXX Hack
     * Aparently pthread_cond_timedwait under openwrt prevents signals (and therefore
     * termination handler) from happening so we need to explicitly kill the threads 
     * that use that
     */
    if (tid_fw_counter && self != tid_fw_counter) {
        debug(LOG_INFO, "Explicitly killing the fw_counter thread");
		pthread_cancel ( tid_fw_counter );
    }
    if (tid_ping && self != tid_ping) {
        debug(LOG_INFO, "Explicitly killing the ping thread");
		pthread_cancel ( tid_ping );
    }

	if ( tid_reload && self != tid_reload )
	{
		debug ( LOG_INFO, "Explicitly killing the tid_reload thread" );
		pthread_cancel ( tid_reload );
	}

	pthread_mutex_unlock ( &client_list_mutex );

	client_list_save ();

    debug(LOG_NOTICE, "Exiting...");
    exit(s == 0 ? 1 : 0);
}

void hup_handler ( int s )
{
	debug ( LOG_INFO, "reload config" );
	hupsignal = 1;
}

/** @internal 
 * Registers all the signal handlers
 */
static void
init_signals(void)
{
    struct sigaction sa;

    debug(LOG_DEBUG, "Initializing signal handlers");

    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        debug(LOG_ERR, "sigaction(): %s", strerror(errno));
        exit(1);
    }

    /* Trap SIGPIPE */
    /* This is done so that when libhttpd does a socket operation on
     * a disconnected socket (i.e.: Broken Pipes) we catch the signal
     * and do nothing. The alternative is to exit. SIGPIPE are harmless
     * if not desirable.
     */
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) == -1) {
        debug(LOG_ERR, "sigaction(): %s", strerror(errno));
        exit(1);
    }

    sa.sa_handler = termination_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    /* Trap SIGTERM */
    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        debug(LOG_ERR, "sigaction(): %s", strerror(errno));
        exit(1);
    }

    /* Trap SIGQUIT */
    if (sigaction(SIGQUIT, &sa, NULL) == -1) {
        debug(LOG_ERR, "sigaction(): %s", strerror(errno));
        exit(1);
    }

    /* Trap SIGINT */
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        debug(LOG_ERR, "sigaction(): %s", strerror(errno));
        exit(1);
    }

	sa.sa_handler = hup_handler;
	sigemptyset ( &sa.sa_mask );
	sa.sa_flags = SA_RESTART;

	if ( sigaction ( SIGHUP, &sa, NULL ) == -1 )
	{
		debug ( LOG_ERR, "sigaction(): %s", strerror ( errno ) );
		exit ( 1 );
	}
}

/**@internal
 * Main execution loop 
 */
static void
main_loop(void)
{
    int result;
    pthread_t tid;
    s_config *config = config_get_config();
    request *r;
    void **params;

    /* Set the time when wifidog started */
    if (!started_time) {
        debug(LOG_INFO, "Setting started_time");
        started_time = time(NULL);
    } else if (started_time < MINIMUM_STARTED_TIME) {
        debug(LOG_WARNING, "Detected possible clock skew - re-setting started_time");
        started_time = time(NULL);
    }

	/* save the pid file if needed */
    if (config->pidfile)
        save_pid_file(config->pidfile);

    /* If we don't have the Gateway IP address, get it. Can't fail. */
    if (!config->gw_address) {
        debug(LOG_DEBUG, "Finding IP address of %s", config->gw_interface);
        if ((config->gw_address = get_iface_ip(config->gw_interface)) == NULL) {
            debug(LOG_ERR, "Could not get IP address information of %s, exiting...", config->gw_interface);
            exit(1);
        }
        debug(LOG_DEBUG, "%s = %s", config->gw_interface, config->gw_address);
    }

	if ( ! config->gw_id )
	{
		debug ( LOG_DEBUG, "Get host name" );

		if ( ( config->gw_id = get_host_name () ) == NULL )
		{
			debug ( LOG_ERR, "Could not get host name information, exiting..." );
			exit ( 1 );
		}

		debug ( LOG_DEBUG, "%s = %s", config->gw_interface, config->gw_id );
	}

    /* Reset the firewall (if WiFiDog crashed) */
    fw_destroy();
    /* Then initialize it */
    if (!fw_init()) {
        debug(LOG_ERR, "FATAL: Failed to initialize firewall");
        exit(1);
    }

	client_list_load ();

	client_list_set_update_flag ( 0 );

    /* Initializes the web server */
    debug ( LOG_NOTICE, "Creating web server on %s:%d", config->gw_address, config->gw_port );
    debug ( LOG_NOTICE, "checkinterval: %d", config->checkinterval );
    debug ( LOG_NOTICE, "clienttimeout: %d", config->clienttimeout );

    if ((webserver = httpdCreate(config->gw_address, config->gw_port)) == NULL) {
        debug(LOG_ERR, "Could not create web server: %s", strerror(errno));
        exit(1);
    }
    register_fd_cleanup_on_fork(webserver->serverSock);

    debug(LOG_DEBUG, "Assigning callbacks to web server");
    
    httpdAddCContent(webserver, "/wifidog", "auth", 0, NULL, http_callback_auth);
    httpdAddCContent(webserver, "/wifidog", "disconnect", 0, NULL, http_callback_disconnect);

    httpdSetErrorFunction(webserver, 404, http_callback_404);

    /* Start clean up thread */
    result = pthread_create(&tid_fw_counter, NULL, (void *)thread_client_timeout_check, NULL);
    if (result != 0) {
        debug(LOG_ERR, "FATAL: Failed to create a new thread (fw_counter) - exiting");
        termination_handler(0);
    }
    pthread_detach(tid_fw_counter);

    /* Start heartbeat thread */
    result = pthread_create(&tid_ping, NULL, (void *)thread_ping, NULL);
    if (result != 0) {
        debug(LOG_ERR, "FATAL: Failed to create a new thread (ping) - exiting");
        termination_handler(0);
    }
    pthread_detach(tid_ping);


	/*
	*	создаём нить для перезагрузки конфигурации
	*/
	result = pthread_create ( &tid_reload, NULL, (void *)thread_reload, NULL );

	if ( result != 0 )
	{
		debug ( LOG_ERR, "FATAL: Failed to create a new thread (reload) - exiting" );
		termination_handler ( 0 );
	}

	debug ( LOG_NOTICE, "Waiting for connections" );

    while (1) {
        r = httpdGetConnection(webserver, NULL);

        /* We can't convert this to a switch because there might be
         * values that are not -1, 0 or 1. */
        if (webserver->lastError == -1) {
            /* Interrupted system call */
            if (NULL != r) {
                httpdEndRequest(r);
            }
        } else if (webserver->lastError < -1) {
            /*
             * FIXME
             * An error occurred - should we abort?
             * reboot the device ?
             */
            debug(LOG_ERR, "FATAL: httpdGetConnection returned unexpected value %d, exiting.", webserver->lastError);
            termination_handler(0);
        } else if (r != NULL) {
            /*
             * We got a connection
             *
             * We should create another thread
             */
            debug(LOG_INFO, "Received connection from %s, spawning worker thread", r->clientAddr);
            /* The void**'s are a simulation of the normal C
             * function calling sequence. */
            params = safe_malloc(2 * sizeof(void *));
            *params = webserver;
            *(params + 1) = r;

            result = pthread_create(&tid, NULL, (void *)thread_httpd, (void *)params);
            if (result != 0) {
                debug(LOG_ERR, "pthread_create return: %d", result );
                debug(LOG_ERR, "FATAL: Failed to create a new thread (httpd) - exiting");
                termination_handler(0);
            }
            pthread_detach(tid);
        } else {
            /* webserver->lastError should be 2 */
            /* XXX We failed an ACL.... No handling because
             * we don't set any... */
        }
    }

    /* never reached */
}

int main ( int argc, char** argv )
{
	s_config* config = config_get_config ();

	config_init ();

	parse_commandline ( argc, argv );

	config_read ( config->configfile );

	config_validate ();

	client_list_init ();

	init_signals ();

	main_loop ();

	return 0;
}
