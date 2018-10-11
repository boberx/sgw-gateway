#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>

#include "debug.h"
#include "safe.h"
#include "conf.h"
#include "commandline.h"

#include "config.h"

/*
 * Holds an argv that could be passed to exec*() if we restart ourselves
 */
char ** restartargv = NULL;

/**
 * A flag to denote whether we were restarted via a parent wifidog, or started normally
 * 0 means normally, otherwise it will be populated by the PID of the parent
 */
pid_t restart_orig_pid = 0;

static void usage ()
{
    fprintf (
        stdout,
        "Usage: sgw-gateway [options]\n\noptions:\n"
        "  -c [filename] Use this config file\n"
        "  -f            Run in foreground\n"
        "  -d <level>    Debug level\n"
        "  -s            Log to syslog\n"
        "  -h            Print usage\n"
        "  -v            Print version information\n"
        "  -q            Force disable print to stderr\n"
        "  -l [filename] Path to auth file\n"
        "  -r            Enable Pre-Authentication\n" );
}

void parse_commandline(int argc, char **argv)
{
    int c;
    int skiponrestart;
    int i;

    s_config *config = config_get_config();

    //MAGIC 3: Our own -x, the pid, and NULL :
    restartargv = safe_malloc((size_t) (argc + 3) * sizeof(char *));
    i = 0;
    restartargv[i++] = safe_strdup(argv[0]);

	while (-1 != (c = getopt(argc, argv, "c:l:hrfd:sw:vx:i:a:qp:")))
	{
		skiponrestart = 0;

		switch ( c )
		{
			case 'q':
				debugconf.log_stderr = 0;
				break;
			case 'r':
				config->preauth = 1;
				break;
        case 'h':
            usage();
            exit(1);
            break;

        case 'c':
            if (optarg) {
                free(config->configfile);
                config->configfile = safe_strdup(optarg);
            }
            break;
		case 'l':
			if ( optarg )
			{
				free ( config->authfile );
				config->authfile = safe_strdup ( optarg );
			}
			break;
        case 'w':
            if (optarg) {
                free(config->wdctl_sock);
                config->wdctl_sock = safe_strdup(optarg);
            }
            break;

        case 'f':
            skiponrestart = 1;
            config->daemon = 0;
            debugconf.log_stderr = 1;
            break;

        case 'd':
            if (optarg) {
                debugconf.debuglevel = atoi(optarg);
            }
            break;

        case 's':
            debugconf.log_syslog = 1;
            break;

        case 'v':
            fprintf(stdout, "This is WiFiDog version " VERSION "\n");
            exit(1);
            break;

        case 'x':
            skiponrestart = 1;
            if (optarg) {
                restart_orig_pid = atoi(optarg);
            } else {
                fprintf(stdout, "The expected PID to the -x switch was not supplied!");
                exit(1);
            }
            break;

        case 'i':
            if (optarg) {
                free(config->internal_sock);
                config->internal_sock = safe_strdup(optarg);
            }
            break;

        case 'a':
            if (optarg) {
                free(config->arp_table_path);
                config->arp_table_path = safe_strdup(optarg);
            } else {
                fprintf(stdout, "You must supply the path to the ARP table with -a!");
                exit(1);
            }
            break;
        case 'p':
            if (optarg) {
                free(config->pidfile);
                config->pidfile = safe_strdup(optarg);
            } else {
                fprintf(stdout, "The expected PID file path to the wifidog was not supplied!\n");
                exit(1);
            }
            break;
        default:
            usage();
            exit(1);
            break;

        }

        if (!skiponrestart) {
            /* Add it to restartargv */
            safe_asprintf(&(restartargv[i++]), "-%c", c);
            if (optarg) {
                restartargv[i++] = safe_strdup(optarg);
            }
        }

    }

    /* Finally, we should add  the -x, pid and NULL to restartargv
     * HOWEVER we cannot do it here, since this is called before we fork to background
     * so we'll leave this job to gateway.c after forking is completed
     * so that the correct PID is assigned
     *
     * We add 3 nulls, and the first 2 will be overridden later
     */
    restartargv[i++] = NULL;
    restartargv[i++] = NULL;
    restartargv[i++] = NULL;
}
