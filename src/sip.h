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

typedef struct app_config_t {
	pj_pool_t *pool;
	pjsua_config cfg;
	pjsua_logging_config log_cfg;
	pjsua_media_config media_cfg;
	pjsua_transport_config udp_cfg;
} app_config_t;

pj_status_t sip_init(struct app_config_t *app_config, unsigned sip_port);
pj_status_t sip_cleanup(struct app_config_t *app_config);
pj_status_t sip_connect(char *server, char *realm, char *uname, char *passwd,
		struct app_config_t *app_config, pjsua_acc_id *acc_id);
pj_status_t sip_disconnect(pjsua_acc_id *acc_id);
pj_status_t sip_dial(pjsua_acc_id acc_id, const char *number,
		const char *sip_domain, pjsua_call_id *call_id);
pj_status_t sip_answer(pjsua_call_id call_id);
pj_status_t sip_hangup(pjsua_call_id call_id);

/** Event handlers **/
static void on_call_state(pjsua_call_id call_id, pjsip_event *e);
static void on_incoming_call(pjsua_acc_id acc_id, pjsua_call_id call_id,
		pjsip_rx_data *rdata);
static void on_call_media_state(pjsua_call_id call_id);
