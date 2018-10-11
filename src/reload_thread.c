#include "reload_thread.h"

char hupsignal = 0;

void thread_reload ( __attribute__((unused)) void* arg )
{
	time_t lt = time ( NULL );

	while ( 1 )
	{
		if ( hupsignal == 1 )
		{
			debug ( LOG_INFO, "Running reload config" );

			hupsignal = 0;

			s_config* config = config_get_config ();

			config_reload ( config->configfile );

			iptables_fw_reinit ();
		}
		else if ( client_list_get_update_flag () == 1 )
		{
			time_t ct = time ( NULL );

			double diff = difftime ( ct, lt );

			if ( diff > 60 )
			{
				lt = ct;

				client_list_save ();

				client_list_set_update_flag ( 0 );
			}
		}

		sleep ( 2 );
	}
}
