/* vim: set et sw=4 ts=4 sts=4 : */
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

/** @file client_list.c
  @brief Client List Functions
  @author Copyright (C) 2004 Alexandre Carmel-Veillex <acv@acv.ca>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include <string.h>

#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "client_list.h"
#include "firewall.h"

static const unsigned int wd_afile_magic = 0xDAF;

static char client_list_uf = 0;

/** @internal
 * Holds a pointer to the first element of the list 
 */
static t_client *firstclient = NULL;

/** @internal
 * Client ID
 */
static volatile unsigned long long client_id = 1;

/**
 * Mutex to protect client_id and guarantee uniqueness.
 */
static pthread_mutex_t client_id_mutex = PTHREAD_MUTEX_INITIALIZER;

/** Global mutex to protect access to the client list */
pthread_mutex_t client_list_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
*	информация о клиенте для записи в файл
*/
struct clbin_t
{
	uint32_t ipa;
	uint8_t  mac[6];
	char     tkn[65];
};

/** Get a new client struct, not added to the list yet
 * @return Pointer to newly created client object not on the list yet.
 */
t_client *
client_get_new(void)
{
    t_client *client;
    client = safe_malloc(sizeof(t_client));
    return client;
}

/** Get the first element of the list of connected clients
 */
t_client *
client_get_first_client(void)
{
    return firstclient;
}

/**
 * Initializes the list of connected clients (client)
 */
void
client_list_init(void)
{
    firstclient = NULL;
}

/** Insert client at head of list. Lock should be held when calling this!
 * @param Pointer to t_client object.
 */
void
client_list_insert_client(t_client * client)
{
    t_client *prev_head;

    pthread_mutex_lock(&client_id_mutex);
    client->id = client_id++;
    pthread_mutex_unlock(&client_id_mutex);
    prev_head = firstclient;
    client->next = prev_head;
    firstclient = client;
}

/** Based on the parameters it receives, this function creates a new entry
 * in the connections list. All the memory allocation is done here.
 * Client is inserted at the head of the list.
 * @param ip IP address
 * @param mac MAC address
 * @param token Token
 * @return Pointer to the client we just created
 */
t_client* client_list_add ( const char* ip, const char* mac, const char* token )
{
	t_client *curclient;

	curclient = client_get_new ();

	curclient->ip = safe_strdup ( ip );

	curclient->mac = safe_strdup ( mac );

	curclient->token = safe_strdup ( token );

	curclient->counters.incoming_delta =
		curclient->counters.outgoing_delta =
			curclient->counters.incoming =
				curclient->counters.incoming_history =
					curclient->counters.outgoing =
						curclient->counters.outgoing_history = 0;

	curclient->counters.last_updated = time(NULL);

	client_list_insert_client ( curclient );

	debug ( LOG_INFO, "Added a new client to linked list: IP: %s Token: %s", ip, token );

	return curclient;
}

/** Duplicate the whole client list to process in a thread safe way
 * MUTEX MUST BE HELD.
 * @param dest pointer TO A POINTER to a t_client (i.e.: t_client **ptr)
 * @return int Number of clients copied
 */
int
client_list_dup(t_client ** dest)
{
    t_client *new, *cur, *top, *prev;
    int copied = 0;

    cur = firstclient;
    new = top = prev = NULL;

    if (NULL == cur) {
        *dest = new;            /* NULL */
        return copied;
    }

    while (NULL != cur) {
        new = client_dup(cur);
        if (NULL == top) {
            /* first item */
            top = new;
        } else {
            prev->next = new;
        }
        prev = new;
        copied++;
        cur = cur->next;
    }

    *dest = top;
    return copied;
}

/** Create a duplicate of a client.
 * @param src Original client
 * @return duplicate client object with next == NULL
 */
t_client *
client_dup(const t_client * src)
{
    t_client *new = NULL;
    
    if (NULL == src) {
        return NULL;
    }
    
    new = client_get_new();

    new->id = src->id;
    new->ip = safe_strdup(src->ip);
    new->mac = safe_strdup(src->mac);
    new->token = safe_strdup(src->token);
    new->counters.incoming = src->counters.incoming;
    new->counters.incoming_history = src->counters.incoming_history;
    new->counters.incoming_delta = src->counters.incoming_delta;
    new->counters.outgoing = src->counters.outgoing;
    new->counters.outgoing_history = src->counters.outgoing_history;
    new->counters.outgoing_delta = src->counters.outgoing_delta;
    new->counters.last_updated = src->counters.last_updated;
    new->next = NULL;

    return new;
}

/** Find a client in the list from a client struct, matching operates by id.
 * This is useful from a copy of client to find the original.
 * @param client Client to find
 * @return pointer to the client in the list.
 */
t_client *
client_list_find_by_client(t_client * client)
{
    t_client *c = firstclient;

    while (NULL != c) {
        if (c->id == client->id) {
            return c;
        }
        c = c->next;
    }
    return NULL;
}

/** Finds a  client by its IP and MAC, returns NULL if the client could not
 * be found
 * @param ip IP we are looking for in the linked list
 * @param mac MAC we are looking for in the linked list
 * @return Pointer to the client, or NULL if not found
 */
t_client *
client_list_find(const char *ip, const char *mac)
{
    t_client *ptr;

    ptr = firstclient;
    while (NULL != ptr) {
        if (0 == strcmp(ptr->ip, ip) && 0 == strcmp(ptr->mac, mac))
            return ptr;
        ptr = ptr->next;
    }

    return NULL;
}

/**
 * Finds a  client by its IP, returns NULL if the client could not
 * be found
 * @param ip IP we are looking for in the linked list
 * @return Pointer to the client, or NULL if not found
 */
t_client *
client_list_find_by_ip(const char *ip)
{
    t_client *ptr;

    ptr = firstclient;
    while (NULL != ptr) {
        if (0 == strcmp(ptr->ip, ip))
            return ptr;
        ptr = ptr->next;
    }

    return NULL;
}

/**
 * Finds a  client by its Mac, returns NULL if the client could not
 * be found
 * @param mac Mac we are looking for in the linked list
 * @return Pointer to the client, or NULL if not found
 */
t_client *
client_list_find_by_mac(const char *mac)
{
    t_client *ptr;

    ptr = firstclient;
    while (NULL != ptr) {
        if (0 == strcmp(ptr->mac, mac))
            return ptr;
        ptr = ptr->next;
    }

    return NULL;
}

/** Finds a client by its token
 * @param token Token we are looking for in the linked list
 * @return Pointer to the client, or NULL if not found
 */
t_client *
client_list_find_by_token(const char *token)
{
    t_client *ptr;

    ptr = firstclient;
    while (NULL != ptr) {
        if (0 == strcmp(ptr->token, token))
            return ptr;
        ptr = ptr->next;
    }

    return NULL;
}

/** Destroy the client list. Including all free...
 * DOES NOT UPDATE firstclient or anything else.
 * @param list List to destroy (first item)
 */
void
client_list_destroy(t_client * list)
{
    t_client *next;

    while (NULL != list) {
        next = list->next;
        client_free_node(list);
        list = next;
    }
}

/** @internal
 * @brief Frees the memory used by a t_client structure
 * This function frees the memory used by the t_client structure in the
 * proper order.
 * @param client Points to the client to be freed
 */
void
client_free_node(t_client * client)
{

    if (client->mac != NULL)
        free(client->mac);

    if (client->ip != NULL)
        free(client->ip);

    if (client->token != NULL)
        free(client->token);

    free(client);
}

/**
 * @brief Deletes a client from the connections list
 *
 * Removes the specified client from the connections list and then calls
 * the function to free the memory used by the client.
 * @param client Points to the client to be deleted
 */
void
client_list_delete(t_client * client)
{
    client_list_remove(client);
    client_free_node(client);
}

/**
 * @brief Removes a client from the connections list
 *
 * @param client Points to the client to be deleted
 */
void
client_list_remove(t_client * client)
{
    t_client *ptr;

    ptr = firstclient;

    if (ptr == NULL) {
        debug(LOG_ERR, "Node list empty!");
    } else if (ptr == client) {
        firstclient = ptr->next;
    } else {
        /* Loop forward until we reach our point in the list. */
        while (ptr->next != NULL && ptr->next != client) {
            ptr = ptr->next;
        }
        /* If we reach the end before finding out element, complain. */
        if (ptr->next == NULL) {
            debug(LOG_ERR, "Node to delete could not be found.");
        } else {
            ptr->next = client->next;
        }
    }
}

char client_list_save ()
{
	const char* logprefix = "save: ";
	char r = 0;
	FILE* file = 0;
	s_config* config = config_get_config ();

	if ( config->authfile == NULL )
		debug ( LOG_WARNING, "%swarning: auth file is not set", logprefix );
	else if ( ( file = fopen ( config->authfile, "w" ) ) == NULL )
		debug ( LOG_ERR, "%serror: opening file: %s", logprefix, config->authfile );
	else
	{
		if ( ftrylockfile ( file ) != 0 )
			debug ( LOG_ERR, "%serror: locking file: %s", logprefix, config->authfile );
		else
		{
			t_client* worklist = NULL;
			t_client* worklist_o = NULL;
			unsigned int desc[2] = { wd_afile_magic, sizeof ( desc ) };
			int cp = 0;

			flockfile ( file );
			debug ( LOG_NOTICE, "%srecording clients to file: %s", logprefix, config->authfile );

			if ( pthread_mutex_trylock ( &client_list_mutex ) != 0 )
				debug ( LOG_ERR, "%serror: pthread_mutex_trylock", logprefix );
			else
			{
				cp = client_list_dup ( &worklist );
				pthread_mutex_unlock ( &client_list_mutex );
				worklist_o = worklist;
			}

			fwrite ( desc, sizeof ( desc ), 1, file );

			if ( ferror ( file ) != 0 )
				debug ( LOG_ERR, "%serror: description auth file write", logprefix );
			else if ( cp > 0 )
			{
				r = 1;

				while ( worklist != NULL )
				{
					t_client* tmp = client_list_find_by_client ( worklist );

					if ( tmp != NULL && tmp->fw_connection_state == FW_MARK_KNOWN )
					{
						struct clbin_t clbin;
						struct in_addr addr;
						int values[6];
						size_t s = 0;

						if ( inet_aton ( worklist->ip, &addr ) == 0 )
						{
							debug ( LOG_ERR, "%serror: invalid ip address: %s", logprefix, worklist->ip );
							break;
						}
						else if ( sscanf (
							worklist->mac,
							"%x:%x:%x:%x:%x:%x",
							&values[0],
							&values[1],
							&values[2],
							&values[3],
							&values[4],
							&values[5] ) != 6 )
						{
							debug ( LOG_ERR, "%serror: invalid mac-address: %s", logprefix, worklist->mac );
							break;
						}
						else
						{
							int i;

							for ( i = 0; i < 6; i ++ )
								clbin.mac[i] = (uint8_t) values[i];

							strncpy ( clbin.tkn, worklist->token, sizeof ( clbin.tkn ) / sizeof ( *clbin.tkn ) );

							clbin.ipa = addr.s_addr;
							s = sizeof ( clbin );

							fwrite ( &clbin, s, 1, file );

							if ( ferror ( file ) != 0 )
							{
								debug ( LOG_ERR, "%serror: writing data to authfile", logprefix );
								r = 0;
								break;
							}
							else
								desc[1] += s;
						}
					}

					worklist = worklist->next;
				}
			}
			else
				debug ( LOG_NOTICE, "%sno clients", logprefix );

			client_list_destroy ( worklist_o );

			fseek ( file, sizeof ( wd_afile_magic ), SEEK_SET );

			fwrite ( &desc[1], sizeof ( desc[1] ), 1, file );

			if ( ferror ( file ) != 0 )
			{
				r = 0;
				debug ( LOG_ERR, "%serror: size file write", logprefix );
			}

			funlockfile ( file );
		}

		fclose ( file );
	}

	return r;
}

char client_list_load ()
{
	const char* logprefix = "load: ";
	char r = 0;
	FILE* file;
	s_config* config = config_get_config ();

	if ( config->authfile == NULL )
		debug ( LOG_WARNING, "%swarning: auth file is not set", logprefix );
	else if ( ( file = fopen ( config->authfile, "r" ) ) == NULL )
		debug ( LOG_WARNING, "%swarning: error opening file: %s", logprefix, config->authfile );
	else
	{
		struct stat sb;

		if ( fstat ( fileno ( file ), &sb ) != 0 )
			debug ( LOG_ERR, "%serror: fstat: %s", logprefix, config->authfile );
		else
		{
			time_t ct = time ( NULL );

			double fage = difftime ( ct, sb.st_mtime );

			if ( fage > 1800 )
				debug ( LOG_WARNING, "%swarning: file too old: %s", logprefix, config->authfile );
			else if ( ftrylockfile ( file ) != 0 )
				debug ( LOG_ERR, "%serror: locking file: %s", logprefix, config->authfile );
			else
			{
				unsigned int desc[2] = {0, 0};

				flockfile ( file );

				if ( fread ( &desc, sizeof ( desc ), 1, file ) != 1 || desc[0] != wd_afile_magic )
					debug ( LOG_ERR, "%sthis is not wd auth file: %s", logprefix, config->authfile );
				else
				{
					debug ( LOG_NOTICE, "%sloading clients from file: %s", logprefix, config->authfile );

					r = 1;
					unsigned int s = sizeof ( desc );

					if ( pthread_mutex_trylock ( &client_list_mutex ) != 0 )
						debug ( LOG_ERR, "%serror: pthread_mutex_lock", logprefix );
					else
					{
						while ( ! feof ( file ) && s < desc[1] )
						{
							struct clbin_t clbin;

							if ( fread ( &clbin, sizeof ( clbin ), 1, file ) != 1 )
							{
								r = 0;
								debug ( LOG_ERR, "error read auth file: %s", config->authfile );
								break;
							}
							else
							{
								s += sizeof ( clbin );

								struct in_addr addr;
								addr.s_addr = clbin.ipa;
								char* ip = inet_ntoa ( addr );
								char mac[18];

								if ( snprintf (
									mac,
									sizeof ( mac ) / sizeof ( *mac ),
									"%02x:%02x:%02x:%02x:%02x:%02x",
									clbin.mac[0],
									clbin.mac[1],
									clbin.mac[2],
									clbin.mac[3],
									clbin.mac[4],
									clbin.mac[5] ) != 17 )
								{
									debug ( LOG_ERR, "%serror: bad auth file", logprefix );
									r = 0;
									break;
								}
								else
								{
									clbin.tkn[sizeof ( clbin.tkn ) / sizeof ( *clbin.tkn ) - 1 ] = 0;
									t_client* client = client_list_add ( ip, mac, clbin.tkn );
									fw_allow ( client, FW_MARK_KNOWN );
								}
							}
						}

						pthread_mutex_unlock ( &client_list_mutex );
					}
				}

				funlockfile ( file );
			}
		}

		fclose ( file );
	}

	return r;
}

void client_list_set_update_flag ( char flag )
{
	static pthread_mutex_t client_list_uf_mutex = PTHREAD_MUTEX_INITIALIZER;

	pthread_mutex_lock ( &client_list_uf_mutex );

	client_list_uf = flag;

	pthread_mutex_unlock ( &client_list_uf_mutex );
}

char client_list_get_update_flag () { return client_list_uf; }
