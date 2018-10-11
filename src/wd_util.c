/* vim: set et sw=4 sts=4 ts=4 : */
/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
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

/**
  @file wd_util.c
  @brief Misc utility functions
  @author Copyright (C) 2015 Alexandre Carmel-Veilleux <acv@miniguru.ca>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>

#include "common.h"
#include "gateway.h"
#include "commandline.h"
#include "client_list.h"
#include "conf.h"
#include "safe.h"
#include "util.h"
#include "wd_util.h"
#include "debug.h"
#include "pstring.h"

#include "config.h"

/* XXX Do these need to be locked ? */
static time_t last_online_time = 0;
static time_t last_offline_time = 0;
static time_t last_auth_online_time = 0;
static time_t last_auth_offline_time = 0;

long served_this_session = 0;

void
mark_online()
{
    int before;
    int after;

    before = is_online();
    time(&last_online_time);
    after = is_online();        /* XXX is_online() looks at last_online_time... */

    if (before != after) {
        debug(LOG_INFO, "ONLINE status became %s", (after ? "ON" : "OFF"));
    }

}

void
mark_offline()
{
    int before;
    int after;

    before = is_online();
    time(&last_offline_time);
    after = is_online();

    if (before != after) {
        debug(LOG_INFO, "ONLINE status became %s", (after ? "ON" : "OFF"));
    }

    /* If we're offline it definately means the auth server is offline */
    mark_auth_offline();

}

int
is_online()
{
    if (last_online_time == 0 || (last_offline_time - last_online_time) >= (config_get_config()->checkinterval * 2)) {
        /* We're probably offline */
        return (0);
    } else {
        /* We're probably online */
        return (1);
    }
}

void
mark_auth_online()
{
    int before;
    int after;

    before = is_auth_online();
    time(&last_auth_online_time);
    after = is_auth_online();

    if (before != after) {
        debug(LOG_INFO, "AUTH_ONLINE status became %s", (after ? "ON" : "OFF"));
    }

    /* If auth server is online it means we're definately online */
    mark_online();

}

void
mark_auth_offline()
{
    int before;
    int after;

    before = is_auth_online();
    time(&last_auth_offline_time);
    after = is_auth_online();

    if (before != after) {
        debug(LOG_INFO, "AUTH_ONLINE status became %s", (after ? "ON" : "OFF"));
    }

}

int
is_auth_online()
{
    if (!is_online()) {
        /* If we're not online auth is definately not online :) */
        return (0);
    } else if (last_auth_online_time == 0
               || (last_auth_offline_time - last_auth_online_time) >= (config_get_config()->checkinterval * 2)) {
        /* Auth is  probably offline */
        return (0);
    } else {
        /* Auth is probably online */
        return (1);
    }
}
