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

#define THIS_FILE	"sip.c"

#include "sipmodem.h"

static pjsua_call_id current_call = PJSUA_INVALID_ID;

pj_status_t sip_init(struct app_config_t *app_config, unsigned sip_port) {
	pj_status_t status;
	pj_str_t codec;
	char tmp[80];

	/* Create pjsua first! */
	status = pjsua_create();
	if (status != PJ_SUCCESS)
		return status;

	/* Create pool for application */
	app_config->pool = pjsua_pool_create("pjsua", 1000, 1000);

	/* Initialize default config */
	pjsua_config_default(&(app_config->cfg));
	app_config->cfg.max_calls = 1;

	pj_ansi_snprintf(tmp, 80, "sipmodem v%s/%s", VERSION, PJ_OS_NAME);
	pj_strdup2_with_null(app_config->pool, &(app_config->cfg.user_agent), tmp);

	pjsua_logging_config_default(&(app_config->log_cfg));
	app_config->log_cfg.msg_logging = PJ_FALSE;
	app_config->log_cfg.console_level = 3;
	app_config->log_cfg.level = 3;

	pjsua_media_config_default(&(app_config->media_cfg));
	app_config->media_cfg.clock_rate = 8000;
	app_config->media_cfg.snd_clock_rate = 8000;
	app_config->media_cfg.channel_count = 1;
	app_config->media_cfg.audio_frame_ptime = 20;
	app_config->media_cfg.ptime = 20;
	app_config->media_cfg.quality = 1;
	app_config->media_cfg.ec_tail_len = 0;
	app_config->media_cfg.jb_init = 60;
	app_config->media_cfg.jb_min_pre = 60;
	app_config->media_cfg.jb_max_pre = 60;
	app_config->media_cfg.jb_max = 60;
	app_config->media_cfg.has_ioqueue = true;
	app_config->media_cfg.thread_cnt = 1;

	pjsua_transport_config_default(&(app_config->udp_cfg));
	app_config->udp_cfg.port = sip_port;

	/* Initialize application callbacks */
	app_config->cfg.thread_cnt = 1;
	app_config->cfg.cb.on_incoming_call = &on_incoming_call;
	app_config->cfg.cb.on_call_media_state = &on_call_media_state;
	app_config->cfg.cb.on_call_state = &on_call_state;

	/* Initialize pjsua */
	status = pjsua_init(&app_config->cfg, &app_config->log_cfg,
			&app_config->media_cfg);
	if (status != PJ_SUCCESS)
		return status;

	/* Add UDP transport. */
	status = pjsua_transport_create(PJSIP_TRANSPORT_UDP, &app_config->udp_cfg,
			NULL/*&transport_id*/);
	if (status != PJ_SUCCESS)
		return status;

	pjsua_set_null_snd_dev();

	pjsua_codec_set_priority(pj_cstr(&codec, "pcmu"), 255);
	pjsua_codec_set_priority(pj_cstr(&codec, "pcma"), 0);
	pjsua_codec_set_priority(pj_cstr(&codec, "speex/8000"), 0);
	pjsua_codec_set_priority(pj_cstr(&codec, "ilbc"), 0);
	pjsua_codec_set_priority(pj_cstr(&codec, "speex/16000"), 0);
	pjsua_codec_set_priority(pj_cstr(&codec, "speex/32000"), 0);
	pjsua_codec_set_priority(pj_cstr(&codec, "gsm"), 0);
	pjsua_codec_set_priority(pj_cstr(&codec, "g722"), 0);

	/* Initialization is done, now start pjsua */
	status = pjsua_start();

	modem_at_init();

	return status;
}

pj_status_t sip_cleanup(struct app_config_t *app_config) {
	pj_status_t status;

	if (app_config->pool) {
		pj_pool_release(app_config->pool);
		app_config->pool = NULL;
	}

	/* Destroy pjsua */
	status = pjsua_destroy();

	pj_bzero(&app_config, sizeof(app_config));

	return status;
}

pj_status_t sip_connect(char *server, char *realm, char *uname, char *passwd,
		struct app_config_t *app_config, pjsua_acc_id *acc_id) {
	pj_status_t status;
	pjsua_acc_config acc_cfg;

	pjsua_acc_config_default(&acc_cfg);

	// ID
	acc_cfg.id.ptr = (char*) pj_pool_alloc(app_config->pool,
	PJSIP_MAX_URL_SIZE);
	acc_cfg.id.slen = pj_ansi_snprintf(acc_cfg.id.ptr, PJSIP_MAX_URL_SIZE,
			"sip:%s@%s", uname, server);
	if (pjsua_verify_sip_url(acc_cfg.id.ptr) != 0) {
		PJ_LOG(1,
				(THIS_FILE, "Error: invalid SIP URL '%s' in local id argument", acc_cfg.id));
		return PJ_EINVAL;
	}

	// Registar
	acc_cfg.reg_uri.ptr = (char*) pj_pool_alloc(app_config->pool,
	PJSIP_MAX_URL_SIZE);
	acc_cfg.reg_uri.slen = pj_ansi_snprintf(acc_cfg.reg_uri.ptr,
	PJSIP_MAX_URL_SIZE, "sip:%s", server);
	if (pjsua_verify_sip_url(acc_cfg.reg_uri.ptr) != 0) {
		PJ_LOG(1,
				(THIS_FILE, "Error: invalid SIP URL '%s' in registrar argument", acc_cfg.reg_uri));
		return PJ_EINVAL;
	}

	//acc_cfg.id = pj_str(id);
	//acc_cfg.reg_uri = pj_str(registrar);
	acc_cfg.cred_count = 1;
	acc_cfg.cred_info[0].scheme = pj_str("Digest");
	acc_cfg.cred_info[0].realm = pj_str(realm);
	acc_cfg.cred_info[0].username = pj_str(uname);
	acc_cfg.cred_info[0].data_type = PJSIP_CRED_DATA_PLAIN_PASSWD;
	acc_cfg.cred_info[0].data = pj_str(passwd);
	acc_cfg.reg_timeout = 3600;
	acc_cfg.rtp_cfg.port = 16000;
	acc_cfg.rtp_cfg.port_range = 16500;

	status = pjsua_acc_add(&acc_cfg, PJ_TRUE, acc_id);
	if (status != PJ_SUCCESS) {
		pjsua_perror(THIS_FILE, "Error adding new account", status);
	}

	return status;
}

pj_status_t sip_disconnect(pjsua_acc_id *acc_id) {
	pj_status_t status = PJ_SUCCESS;

	if (pjsua_acc_is_valid(*acc_id)) {
		status = pjsua_acc_del(*acc_id);
		if (status == PJ_SUCCESS)
			*acc_id = PJSUA_INVALID_ID;
	}

	return status;
}

pj_status_t sip_dial(pjsua_acc_id acc_id, const char *number,
		const char *sip_domain, pjsua_call_id *call_id) {
	pj_status_t status = PJ_SUCCESS;
	char uri[256];
	pj_str_t pj_uri;

	pj_ansi_snprintf(uri, 256, "sip:%s@%s", number, sip_domain);
	PJ_LOG(5, (THIS_FILE, "Calling URI \"%s\".", uri));

	status = pjsua_verify_sip_url(uri);
	if (status != PJ_SUCCESS) {
		PJ_LOG(1, (THIS_FILE, "Invalid URL \"%s\".", uri));
		pjsua_perror(THIS_FILE, "Invalid URL", status);
		return status;
	}

	pj_uri = pj_str(uri);

	status = pjsua_call_make_call(acc_id, &pj_uri, 0, NULL, NULL, call_id);
	if (status != PJ_SUCCESS) {
		pjsua_perror(THIS_FILE, "Error making call", status);
	}

	return status;

}

pj_status_t sip_answer(pjsua_call_id call_id) {
	pj_status_t status;
	status = pjsua_call_answer(call_id, 200, NULL, NULL);
	return status;
}

pj_status_t sip_hangup(pjsua_call_id call_id) {
	pj_status_t status = PJ_SUCCESS;
	if (pjsua_call_is_active(call_id)) {
		sipmodem.call_id = 0;
		status = pjsua_call_hangup(call_id, 0, NULL, NULL);
	}
	return status;
}

/** Event Handlers **/

/* Callback called by the library upon receiving incoming call */
static void on_incoming_call(pjsua_acc_id acc_id, pjsua_call_id call_id,
		pjsip_rx_data *rdata) {
	PJ_UNUSED_ARG(acc_id);
	PJ_UNUSED_ARG(rdata);
	sipmodem.call_id = call_id;

	/* Trigger AT_CALL_EVENT_ALERTING RING event */
	PJ_LOG(1, (THIS_FILE, "Incoming call"));
	at_call_event(sipmodem.at_state, AT_CALL_EVENT_ALERTING);
}

/* Callback called by the library when call's state has changed */
static void on_call_state(pjsua_call_id call_id, pjsip_event *e) {
	pjsua_call_info ci;
	PJ_UNUSED_ARG(e);
	sipmodem.call_id = call_id;
	pjsua_call_get_info(call_id, &ci);
	PJ_LOG(3,
			(THIS_FILE, "Call %d state=%.*s", call_id, (int)ci.state_text.slen, ci.state_text.ptr));

	switch (ci.state) {
	case PJSIP_INV_STATE_CONFIRMED:
		PJ_LOG(3, (THIS_FILE, "Call %d modem_init", call_id));
		PJ_LOG(3, (THIS_FILE, "Call last status %d", ci.last_status));
		sleep(1);
		modem_init(call_id);
		modem_conf_connect(call_id);
		break;
	case PJSIP_INV_STATE_DISCONNECTED:
		PJ_LOG(3, (THIS_FILE, "Call %d modem_cleanup", call_id));
		sipmodem.at_state->rx_signal_present = false;
		sp_set_dtr(sipmodem.sp_port, SP_DTR_OFF);
		sp_flush(sipmodem.sp_port, SP_BUF_BOTH);
		switch (ci.last_status) {
		case PJSIP_SC_BAD_REQUEST:
		case PJSIP_SC_UNAUTHORIZED:
		case PJSIP_SC_PAYMENT_REQUIRED:
		case PJSIP_SC_FORBIDDEN:
		case PJSIP_SC_REQUEST_TIMEOUT:
		case PJSIP_SC_GONE:
			at_call_event(sipmodem.at_state, AT_CALL_EVENT_NO_DIALTONE);
			break;
		case PJSIP_SC_BUSY_HERE:
			at_call_event(sipmodem.at_state, AT_CALL_EVENT_BUSY);
			break;
		default:
			sipmodem.at_state->dte_is_waiting = true;
			sipmodem.at_state->ok_is_pending = false;
			at_call_event(sipmodem.at_state, AT_CALL_EVENT_HANGUP);
			break;
		}
		modem_conf_disconnect(call_id);
		modem_cleanup(call_id);
		sipmodem.call_id = 0;
		break;
	}
}

/* Callback called by the library when call's media state has changed */
static void on_call_media_state(pjsua_call_id call_id) {
	pjsua_call_info ci;
	pjsua_call_get_info(call_id, &ci);
	sipmodem.call_id = call_id;

	switch (ci.media_status) {
	case PJSUA_CALL_MEDIA_ACTIVE:
		if (ci.state == PJSIP_INV_STATE_CONFIRMED) {
			PJ_LOG(3,
					(THIS_FILE, "Connecting modem. Conf slot: %i", ci.conf_slot));
			modem_conf_connect(call_id);
		}
		break;
	}
}
