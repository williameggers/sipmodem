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

#define THIS_FILE			"modem.c"
#define MODEM_SRATE			8000
#define PTIME				20
#define CHANNEL_COUNT		1
#define BITS_PER_SAMPLE		16
#define SAMPLES_PER_FRAME	(CHANNEL_COUNT * MODEM_SRATE * PTIME / 1000)
#define BYTES_PER_FRAME		SAMPLES_PER_FRAME * BITS_PER_SAMPLE / 8
#define SYMBOL_NOTHING		254

#include "sipmodem.h"

#define PROTOCOLS_USED		V8_MOD_V21 /*| V8_MOD_V22 | V8_MOD_V23*/ | 0

static void spandsp_message_handler(void *user_data, int level, const char *text) {
	PJ_LOG(3, (THIS_FILE, "%s", text));
}

static void modem_log_supported_modulations(data_modems_state_t *s,
		int modulation_schemes) {
	const char *comma;
	int i;

	comma = "";
	span_log(&s->logging, SPAN_LOG_FLOW, "    ");
	for (i = 0; i < 32; i++) {
		if ((modulation_schemes & (1 << i))) {
			span_log(&s->logging, SPAN_LOG_FLOW | SPAN_LOG_SUPPRESS_LABELLING,
					"%s%s", comma,
					v8_modulation_to_str(modulation_schemes & (1 << i)));
			comma = ", ";
		}
	}
	span_log(&s->logging, SPAN_LOG_FLOW | SPAN_LOG_SUPPRESS_LABELLING,
			" supported\n");
}

/** Hayes AT command callback **/
static int modem_at_control(void *user_data, int op, const char *num) {
	pj_status_t status;

	switch (op) {
	case AT_MODEM_CONTROL_CALL:
		sipmodem.calling_party = true;
		status = sip_dial(sipmodem.acc_id, num, sipmodem.sip.domain,
				&sipmodem.call_id);
		if (status == PJ_SUCCESS) {
			return 0;
		}
		/* Force an error response */
		return -1;
	case AT_MODEM_CONTROL_ANSWER:
		PJ_LOG(1, (THIS_FILE, "Modem control - Answering"));
		sipmodem.calling_party = false;
		status = sip_answer(sipmodem.call_id);
		if (status == PJ_SUCCESS) {
			return 0;
		}
		/* Force an error response */
		return -1;
	case AT_MODEM_CONTROL_HANGUP:
		PJ_LOG(1, (THIS_FILE, "Modem control - Hanging up"));
		sip_hangup(sipmodem.call_id);
		return 0;
	case AT_MODEM_CONTROL_OFFHOOK:
		PJ_LOG(1, (THIS_FILE, "Modem control - Going off hook"));
		break;
	case AT_MODEM_CONTROL_ONHOOK:
		PJ_LOG(1, (THIS_FILE, "Modem control - Going on hook"));
		sip_hangup(sipmodem.call_id);
		break;
	case AT_MODEM_CONTROL_DTR:
		PJ_LOG(1,
				(THIS_FILE, "Modem control - DTR %d\n", (int) (intptr_t) num));
		break;
	case AT_MODEM_CONTROL_RTS:
		PJ_LOG(1,
				(THIS_FILE, "Modem control - RTS %d\n", (int) (intptr_t) num));
		break;
	case AT_MODEM_CONTROL_CTS:
		PJ_LOG(1,
				(THIS_FILE, "Modem control - CTS %d\n", (int) (intptr_t) num));
		break;
	case AT_MODEM_CONTROL_CAR:
		PJ_LOG(1,
				(THIS_FILE, "Modem control - CAR %d\n", (int) (intptr_t) num));
		break;
	case AT_MODEM_CONTROL_RNG:
		PJ_LOG(1,
				(THIS_FILE, "Modem control - RNG %d\n", (int) (intptr_t) num));
		break;
	case AT_MODEM_CONTROL_DSR:
		PJ_LOG(1,
				(THIS_FILE, "Modem control - DSR %d\n", (int) (intptr_t) num));
		break;
	case AT_MODEM_CONTROL_SETID:
		PJ_LOG(1, (THIS_FILE, "Modem control - Set ID '%s'\n", num));
		break;
	case AT_MODEM_CONTROL_RESTART:
		PJ_LOG(1,
				(THIS_FILE, "Modem control - Restart %d\n", (int) (intptr_t) num));
		break;
	case AT_MODEM_CONTROL_DTE_TIMEOUT:
		PJ_LOG(1,
				(THIS_FILE, "Modem control - Set DTE timeout %d", (int) (intptr_t) num));
		break;
	default:
		PJ_LOG(1, (THIS_FILE, "Modem control - operation %d", op));
		break;
	}
	/*endswitch*/
	return 0;
}

/** v8bis modem handler callback **/
static void modem_v8_handler(void *user_data, v8_parms_t *result) {
	data_modems_state_t *s;
	s = (data_modems_state_t *) user_data;
	span_log_set_level(&s->logging, SPAN_LOG_FLOW);

	switch (result->status) {
	case V8_STATUS_IN_PROGRESS:
		span_log(&s->logging, SPAN_LOG_FLOW, "V.8 negotiation in progress\n");
		return;
	case V8_STATUS_V8_OFFERED:
		span_log(&s->logging, SPAN_LOG_FLOW,
				"V.8 offered by the other party\n");
		break;
	case V8_STATUS_V8_CALL:
		span_log(&s->logging, SPAN_LOG_FLOW,
				"V.8 call negotiation successful\n");
		at_call_event(sipmodem.at_state, AT_CALL_EVENT_CONNECTED);
		sipmodem.at_state->dte_rate = s->queued_bit_rate;
		sp_set_dtr(sipmodem.sp_port, SP_DTR_ON);
		break;
	case V8_STATUS_NON_V8_CALL:
		span_log(&s->logging, SPAN_LOG_FLOW,
				"Non-V.8 call negotiation successful\n");
		at_call_event(sipmodem.at_state, AT_CALL_EVENT_CONNECTED);
		sipmodem.at_state->dte_rate = s->queued_bit_rate;
		sp_set_dtr(sipmodem.sp_port, SP_DTR_ON);
		break;
	case V8_STATUS_FAILED:
		span_log(&s->logging, SPAN_LOG_FLOW, "V.8 call negotiation failed\n");
		at_call_event(sipmodem.at_state, AT_CALL_EVENT_HANGUP);
		return;
	default:
		span_log(&s->logging, SPAN_LOG_FLOW, "Unexpected V.8 status %d\n",
				result->status);
		at_call_event(sipmodem.at_state, AT_CALL_EVENT_HANGUP);
		break;
	}
	/*endswitch*/

	span_log(&s->logging, SPAN_LOG_FLOW, "  Modem connect tone '%s' (%d)\n",
			modem_connect_tone_to_str(result->modem_connect_tone),
			result->modem_connect_tone);
	span_log(&s->logging, SPAN_LOG_FLOW, "  Call function '%s' (%d)\n",
			v8_call_function_to_str(result->call_function),
			result->call_function);
	span_log(&s->logging, SPAN_LOG_FLOW, "  Far end modulations 0x%X\n",
			result->modulations);
	modem_log_supported_modulations(s, result->modulations);
	span_log(&s->logging, SPAN_LOG_FLOW, "  Protocol '%s' (%d)\n",
			v8_protocol_to_str(result->protocol), result->protocol);
	span_log(&s->logging, SPAN_LOG_FLOW, "  PSTN access '%s' (%d)\n",
			v8_pstn_access_to_str(result->pstn_access), result->pstn_access);
	span_log(&s->logging, SPAN_LOG_FLOW, "  PCM modem availability '%s' (%d)\n",
			v8_pcm_modem_availability_to_str(result->pcm_modem_availability),
			result->pcm_modem_availability);
	if (result->t66 >= 0)
		span_log(&s->logging, SPAN_LOG_FLOW, "  T.66 '%s' (%d)\n",
				v8_t66_to_str(result->t66), result->t66);
	/*endif*/
	if (result->nsf >= 0)
		span_log(&s->logging, SPAN_LOG_FLOW, "  NSF %d\n", result->nsf);
	/*endif*/

	switch (result->status) {
	case V8_STATUS_V8_OFFERED:
		/* V.8 mode has been offered. */
		span_log(&s->logging, SPAN_LOG_FLOW, "  Offered\n");
		/* We now need to edit the offered list of usable modem modulations to reflect
		 the set of modulations both ends share */
		result->modulations &= (PROTOCOLS_USED);
		span_log(&s->logging, SPAN_LOG_FLOW, "  Mutual modulations 0x%X\n",
				result->modulations);
		modem_log_supported_modulations(s, result->modulations);
		break;
	case V8_STATUS_V8_CALL:
		span_log(&s->logging, SPAN_LOG_FLOW, "  Call\n");
		if (result->call_function == V8_CALL_V_SERIES) {
			/* Negotiations OK */
			if (result->protocol == V8_PROTOCOL_LAPM_V42) {
			}
			/*endif*/

			if ((result->modulations & V8_MOD_V22)) {
				s->queued_baud_rate = 600;
				s->queued_bit_rate = 2400;
				s->queued_modem = DATA_MODEM_V22BIS;
			} else if ((result->modulations & V8_MOD_V23)) {
				s->queued_baud_rate = 1200;
				s->queued_bit_rate = 1200;
				s->queued_modem = DATA_MODEM_V23;
			} else if ((result->modulations & V8_MOD_V21)) {
				s->queued_baud_rate = 300;
				s->queued_bit_rate = 300;
				s->queued_modem = DATA_MODEM_V21;
			} else {
				s->queued_modem = DATA_MODEM_NONE;
			}
			/*endif*/
			span_log(&s->logging, SPAN_LOG_FLOW,
					"  Negotiated modulation '%s' %d\n",
					data_modems_modulation_to_str(s->queued_modem),
					s->queued_modem);
		}
		/*endif*/
		break;
	case V8_STATUS_NON_V8_CALL:
		span_log(&s->logging, SPAN_LOG_FLOW, "  Non-V.8 call\n");
		s->queued_modem = DATA_MODEM_V21;
		break;
	default:
		span_log(&s->logging, SPAN_LOG_FLOW, "  Huh? %d\n", result->status);
		break;
	}
	/*endswitch*/
}

/** Initialize v8bis modem **/
pj_status_t modem_init_v8(data_modems_state_t *s) {
	v8_parms_t v8_parms;
	logging_state_t *logging;
	int level;

	s->rx_handler = (span_rx_handler_t) &v8_rx;
	s->rx_fillin_handler = (span_rx_fillin_handler_t) &span_dummy_rx_fillin;
	s->rx_user_data = &s->modems.v8;
	s->tx_handler = (span_tx_handler_t) &v8_tx;
	s->tx_user_data = &s->modems.v8;
	if (s->calling_party)
		v8_parms.modem_connect_tone = MODEM_CONNECT_TONES_NONE;
	else
		v8_parms.modem_connect_tone = MODEM_CONNECT_TONES_ANSAM_PR;
	v8_parms.send_ci = true;
	v8_parms.v92 = -1;
	v8_parms.call_function = V8_CALL_V_SERIES;
	v8_parms.modulations = PROTOCOLS_USED;
	v8_parms.protocol = V8_PROTOCOL_NONE;
	v8_parms.pcm_modem_availability = 0;
	v8_parms.pstn_access = V8_PSTN_ACCESS_DCE_ON_DIGITAL;
	v8_parms.nsf = -1;
	v8_parms.t66 = -1;
	v8_init(&s->modems.v8, s->calling_party, &v8_parms, (v8_result_handler_t)modem_v8_handler,
			(void *) s);
	logging = v8_get_logging_state(&s->modems.v8);
	logging->span_message = &spandsp_message_handler;
	span_log_set_level(logging, 9);
	span_log_set_tag(logging, "V.8");
	s->current_modem = DATA_MODEM_V8;
	s->queued_modem = s->current_modem;

	return PJ_SUCCESS;
}

/*
 * Create a media port to generate sine wave samples.
 */
pj_status_t modem_create_port(pj_pool_t *pool, unsigned sampling_rate,
		unsigned channel_count, unsigned samples_per_frame,
		unsigned bits_per_sample, pjmedia_port **p_port) {
	struct modem_port *modem_port;
	pj_str_t name;

	PJ_ASSERT_RETURN(pool && channel_count == 1, PJ_EINVAL);

	/* Fill in port info. */
	modem_port = PJ_POOL_ZALLOC_T(pool, struct modem_port);
	name = pj_str("modem");
	pjmedia_port_info_init(&modem_port->base.info, &name,
			PJMEDIA_SIG_CLASS_PORT_AUD('M', 'O'), sampling_rate, channel_count,
			bits_per_sample, samples_per_frame);

	/** Initialize data modem **/
	modem_port->modulator_frames = malloc(MODEM_SRATE * sizeof(int16_t));
	modem_port->demodulator_frames = malloc(MODEM_SRATE * sizeof(int16_t));
	modem_port->modem = data_modems_init(NULL, sipmodem.calling_party,
			&modem_put_msg, &modem_get_msg, modem_port);
	modem_port->modem->logging.span_message =
			(message_handler_func_t) spandsp_message_handler;
	data_modems_set_async_mode(modem_port->modem, 8, 0, 1);
	/** Override default v8bis modem configuration **/
	sipmodem.at_state->fclass_mode = 0;
	modem_init_v8(modem_port->modem);

	/* Set the function to feed frame */
	modem_port->base.get_frame = &modem_get_frame;
	modem_port->base.put_frame = &modem_put_frame;
	modem_port->base.on_destroy = &modem_on_destroy;

	*p_port = &modem_port->base;

	return PJ_SUCCESS;
}

pj_status_t modem_init(pjsua_call_id call_id) {
	struct modem_call_data *modem_call_data;
	pj_pool_t *pool;
	pj_status_t status;
	pjsua_call_info ci;
	pjsua_conf_port_info cpi;

	pool = pjsua_pool_create("modem", 1000, 1000);
	modem_call_data = PJ_POOL_ZALLOC_T(pool, struct modem_call_data);
	modem_call_data->pool = pool;

	status = pjsua_conf_get_port_info(call_id, &cpi);

	PJ_LOG(3, (THIS_FILE, "Samples per frame: %u", cpi.samples_per_frame));
	PJ_LOG(3, (THIS_FILE, "Bits per samples: %u", cpi.bits_per_sample));
	PJ_LOG(3, (THIS_FILE, "Number of channels: %u", cpi.channel_count));
	PJ_LOG(3, (THIS_FILE, "Format: %u", cpi.format));
	PJ_LOG(3, (THIS_FILE, "Port Name: %u", cpi.name));
	PJ_LOG(3, (THIS_FILE, "Clock Rate: %u", cpi.clock_rate));

	/* Create a media port to generate samples. */
	status = modem_create_port(modem_call_data->pool, MODEM_SRATE,
	CHANNEL_COUNT, SAMPLES_PER_FRAME, BITS_PER_SAMPLE, &modem_call_data->port);

	if (status == PJ_SUCCESS) {
		pjsua_conf_add_port(modem_call_data->pool, modem_call_data->port,
				&modem_call_data->slot);
		pjsua_call_set_user_data(call_id, (void*) modem_call_data);
	} else {
		pjsua_perror(THIS_FILE, "Error: Error creating modem port", status);
		pj_pool_release(pool);
		modem_call_data = NULL;
	}

	return status;
}

void modem_at_init() {
	if ((sipmodem.at_state = at_init(NULL, (at_tx_handler_t) &serial_write,
			NULL, &modem_at_control, NULL)) == NULL) {
		pjsua_perror(THIS_FILE, "Error: Cannot start the AT interpreter",
				PJ_FALSE);
	}
}

pj_status_t modem_cleanup(pjsua_call_id call_id) {
	pjsua_call_info ci;
	pj_status_t status;
	struct modem_call_data *modem_call_data;

	pjsua_call_get_info(call_id, &ci);
	modem_call_data = (struct modem_call_data *) pjsua_call_get_user_data(
			call_id);

	if (!modem_call_data)
		return PJ_SUCCESS;

	status = pjsua_conf_remove_port(modem_call_data->slot);
	if (status == PJ_SUCCESS) {
		pjmedia_port_destroy(modem_call_data->port);
		pj_pool_release(modem_call_data->pool);
		pjsua_call_set_user_data(call_id, NULL);
	}

	queue_flush(sipmodem.queue_tx);

	return status;
}

pj_status_t modem_conf_connect(pjsua_call_id call_id) {
	pjsua_call_info ci;
	pj_status_t status;
	struct modem_call_data *modem_call_data;

	pjsua_call_get_info(call_id, &ci);
	modem_call_data = (struct modem_call_data *) pjsua_call_get_user_data(
			call_id);

	if (!modem_call_data)
		return PJ_FALSE;

	status = pjsua_conf_connect(modem_call_data->slot, ci.conf_slot);
	if (status == PJ_SUCCESS) {
		status = pjsua_conf_connect(ci.conf_slot, modem_call_data->slot);
		status = pjsua_conf_connect(modem_call_data->slot, 0);
	}

	return status;
}

pj_status_t modem_conf_disconnect(pjsua_call_id call_id) {
	pjsua_call_info ci;
	pj_status_t status;
	struct modem_call_data *modem_call_data;

	pjsua_call_get_info(call_id, &ci);
	modem_call_data = (struct modem_call_data *) pjsua_call_get_user_data(
			call_id);

	if (!modem_call_data)
		return PJ_FALSE;

	pjsua_conf_disconnect(modem_call_data->slot, ci.conf_slot);
	pjsua_conf_disconnect(ci.conf_slot, modem_call_data->slot);
	pjsua_conf_disconnect(modem_call_data->slot, 0);

	return status;
}

/* This callback is called to feed more samples to the demodulator */
pj_status_t modem_put_frame(pjmedia_port *port, pjmedia_frame *frame) {
	struct modem_port *modem_port = (struct modem_port*) port;

	if (!modem_port->modem) {
		PJ_LOG(3, (THIS_FILE, "Error: modem_port->modem == NULL"));
		return PJ_FALSE;
	}

	if (frame->size > 0) {
		pj_memcpy(modem_port->demodulator_frames, frame->buf, frame->size);
		data_modems_rx(modem_port->modem,
				(const pj_int16_t*) modem_port->demodulator_frames,
				(frame->size * 8 / BITS_PER_SAMPLE));
	} else {
		PJ_LOG(4, (THIS_FILE, "modem_put_frame: frame->size == 0"));
	}

	return PJ_SUCCESS;
}

/* This callback is called to feed more samples from the modulator */
pj_status_t modem_get_frame(pjmedia_port *port, pjmedia_frame *frame) {
	struct modem_port *modem_port = (struct modem_port*) port;
	pj_size_t samples_per_frame;
	pj_status_t status;
	int len;

	if (!modem_port->modem) {
		PJ_LOG(3, (THIS_FILE, "Error: modem_port->modem == NULL"));
		return PJ_FALSE;
	}

	/* Copy frame from buffer. */
	pj_bzero(frame, sizeof(frame));
	if ((len = data_modems_tx(modem_port->modem, modem_port->modulator_frames,
	SAMPLES_PER_FRAME)) <= 0) {
		frame->type = PJMEDIA_FRAME_TYPE_NONE;
		frame->size = 0;
	} else {
		frame->size = BYTES_PER_FRAME;
		frame->type = PJMEDIA_FRAME_TYPE_AUDIO;
		pj_memcpy(frame->buf, (pj_int16_t*) modem_port->modulator_frames,
				(pj_size_t) BYTES_PER_FRAME);
	}

	return PJ_SUCCESS;
}

pj_status_t modem_on_destroy(pjmedia_port *port) {
	struct modem_port *modem_port = (struct modem_port*) port;
	data_modems_release(modem_port->modem);
	data_modems_free(modem_port->modem);
	return PJ_SUCCESS;
}

void modem_modqueue_append(uint8_t *buf, int len) {
	int written;
	written = queue_write(sipmodem.queue_tx, buf, len);
	if (written != len)
		PJ_LOG(3,
				(THIS_FILE, "modem_modqueue_append: wanted to write %d, but %d written !", len, written));
}

int modem_modqueue_isready() {
	int free;
	free = queue_free_space(sipmodem.queue_tx);
	PJ_LOG(4, (THIS_FILE, "modem modqueue_isready, queue %d free", free));
	return free;
}

/** Triggered by spandsp on reception of a new bit to send to the line **/
int modem_get_msg(void *user_data, uint8_t *msg, int max_len) {
	int b;
	b = queue_read_byte(sipmodem.queue_tx);
	if (b < 0)
		b = SYMBOL_NOTHING;
	msg[0] = b;
}

/** Triggered by spandsp on reception of new byte from the line **/
void modem_put_msg(void *user_data, const uint8_t *msg, int len) {
	data_modems_state_t *modem = (data_modems_state_t*) user_data;
	int i;
	if (len < 0) {
		PJ_LOG(1,
				(THIS_FILE, "FSK rx status is %s (%d)", signal_status_to_str(len), len));
		if (len == SIG_STATUS_CARRIER_UP) {
			sipmodem.at_state->rx_signal_present = true;
		} else if (len == SIG_STATUS_CARRIER_DOWN) {
			sipmodem.at_state->rx_signal_present = false;
		}
	} else {
		//PJ_LOG(1, (THIS_FILE, "%i", msg[0]));
		if (msg[0] == SYMBOL_NOTHING)
			return;
		if (sipmodem.at_state->at_rx_mode == AT_MODE_CONNECTED)
			serial_write(NULL, (uint8_t*) msg, len);
	}
}
