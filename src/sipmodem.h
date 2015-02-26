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

#include <stdarg.h>
#include <signal.h>
#include <spandsp.h>
#include <pjsua-lib/pjsua.h>
#include <pjmedia.h>
#include <pjlib.h>
#include <libserialport.h>

#include "sip.h"
#include "modem.h"
#include "serial.h"

#define VERSION				"1.0"
#define SIP_DOMAIN			"127.0.0.1"
#define SIP_USER			"102"
#define SIP_PASSWD			"password"
#define QUEUE_TX_SIZE 		1024

struct {
	/* Can be changed in realtime */
	volatile sig_atomic_t on;
	volatile sig_atomic_t sigrestart;
	volatile sig_atomic_t sigbreak_local;
	volatile sig_atomic_t sigbreak_send;

	struct {
		char* domain;
		char* realm;
		char* username;
		char* password;
		unsigned port;
	} sip;

	struct sp_port *sp_port;
	unsigned sp_dsr_state;
	pjsua_call_id call_id;
	pjsua_acc_id acc_id;
	app_config_t app_config;
	at_state_t *at_state;

	/* Are we the caller or the answerer */
	bool calling_party;

	queue_state_t *queue_tx;
} sipmodem;

