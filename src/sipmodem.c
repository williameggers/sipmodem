/*
 * Copyright (C) 2015 William Eggers <william@eggers.id.au>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#define THIS_FILE	"sipmodem.c"

#include <signal.h>
#include <stdio.h>
#include <cfg2.h>
#include "sipmodem.h"

void signal_handler(int signal) {
	PJ_LOG(1, (THIS_FILE, "Received signal %d", signal));
	switch (signal) {
	case SIGQUIT:
	case SIGINT:
	case SIGTERM:
		sipmodem.on = 0;
		break;
	case SIGUSR1:
		sipmodem.sigrestart = 1;
		break;
	case SIGUSR2:
		sipmodem.sigbreak_local = 1;
		sipmodem.sigbreak_send = 1;
		break;
	}
}

// helper for parsing command-line-argument
static int try_get_argument(int arg, char *arg_id, char **arg_val, int argc,
		char *argv[]) {
	int found = 0;

	// check if actual argument is searched argument
	if (!strcasecmp(argv[arg], arg_id)) {
		// check if actual argument has a value
		if (argc >= (arg + 1)) {
			// set value
			*arg_val = argv[arg + 1];
			found = 1;
		}
	}
	return found;
}

// helper for displaying usage infos
static void show_usage(int error) {
	if (error <= 1) {
		puts("Error, insufficient arguments.");
		puts("");
	}
	puts("Usage:");
	puts("");
	puts("  sipmodem [options]...");
	puts("");
	puts("Mandatory options:");
	puts("");
	puts("  -c CONFIG_FILE\tSet the config file");
	puts("");
	puts("Example:");
	puts("");
	puts("  sipmodem -c sipmodem.cfg");
	puts("");

	fflush(stdout);
}

/*
 * main()
 *
 * argv[1] may contain URL to call.
 */
int main(int argc, char *argv[]) {
	int err;
	cfg_t st;
	char *config_file;
	pj_status_t status;

	signal(SIGQUIT, signal_handler);
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGUSR1, signal_handler);
	signal(SIGUSR2, signal_handler);

	// Parse arguments
	if (argc >= 2) {
		int arg;
		for (arg = 1; arg < argc; arg += 2) {
			if (!strcasecmp(argv[arg], "--help")) {
				show_usage(0);
				exit(0);
			}
			if (try_get_argument(arg, "-c", &config_file, argc, argv) == 1) {
				continue;
			}
		}
	} else {
		show_usage(1);
		exit(1);
	}

	cfg_init(&st, 10);
	err = cfg_parse_file(&st, config_file);
	if (err > 0) {
		printf("Failure reading config file\n");
		exit(1);
	}

	sipmodem.sip.domain = cfg_value_get(&st, "sip_domain");
	sipmodem.sip.realm = cfg_value_get(&st, "sip_realm");
	sipmodem.sip.username = cfg_value_get(&st, "sip_username");
	sipmodem.sip.password = cfg_value_get(&st, "sip_password");
	sipmodem.sip.port = cfg_value_get_ulong(&st, "sip_port", 0);

	sip_init(&sipmodem.app_config, sipmodem.sip.port);
	serial_init(cfg_value_get(&st, "serial_device"),
			cfg_value_get_ulong(&st, "serial_baudrate", 0));

	sip_connect(sipmodem.sip.domain, sipmodem.sip.realm, sipmodem.sip.username,
			sipmodem.sip.password, &sipmodem.app_config, &sipmodem.acc_id);
	sipmodem.on = true;
	sipmodem.queue_tx = queue_init(NULL, QUEUE_TX_SIZE,
	QUEUE_READ_ATOMIC | QUEUE_WRITE_ATOMIC);

	PJ_LOG(1, (THIS_FILE, "sipmodem version %s initialized", VERSION));

	serial_read_loop();

	at_free(sipmodem.at_state);
	sip_disconnect(&sipmodem.acc_id);
	sip_cleanup(&sipmodem.app_config);
	cfg_free(&st);

	return 0;
}
