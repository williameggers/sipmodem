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

#include <spandsp/private/logging.h>
#include <spandsp/private/silence_gen.h>
#include <spandsp/private/power_meter.h>
#include <spandsp/private/fsk.h>
#include <spandsp/private/v22bis.h>
#if defined(SPANDSP_SUPPORT_V32BIS)
#include <spandsp/private/v17tx.h>
#include <spandsp/private/v17rx.h>
#include <spandsp/private/modem_echo.h>
#include <spandsp/private/v32bis.h>
#endif
#if defined(SPANDSP_SUPPORT_V34)
#include <spandsp/private/bitstream.h>
#include <spandsp/private/v34.h>
#endif
#include <spandsp/private/modem_connect_tones.h>
#include <spandsp/private/hdlc.h>
#include <spandsp/private/v42.h>
#include <spandsp/private/v42bis.h>
#include <spandsp/private/v8.h>
#include <spandsp/private/async.h>
#include <spandsp/private/data_modems.h>
#include <spandsp/private/at_interpreter.h>

struct modem_port {
	pjmedia_port base;
	data_modems_state_t *modem;
	int16_t *modulator_frames;
	int16_t *demodulator_frames;
};

struct modem_call_data {
	pj_pool_t *pool;
	pjmedia_port *port;
	pjsua_conf_port_id slot;
};

pj_status_t modem_create_port(pj_pool_t *pool, unsigned sampling_rate,
		unsigned channel_count, unsigned samples_per_frame,
		unsigned bits_per_sample, pjmedia_port **p_port);
pj_status_t modem_init(pjsua_call_id call_id);
pj_status_t modem_init_v8(data_modems_state_t *s);
pj_status_t modem_cleanup(pjsua_call_id call_id);
pj_status_t modem_conf_connect(pjsua_call_id call_id);
pj_status_t modem_conf_disconnect(pjsua_call_id call_id);
pj_status_t modem_put_frame(pjmedia_port *port, pjmedia_frame *frame);
pj_status_t modem_get_frame(pjmedia_port *port, pjmedia_frame *frame);
pj_status_t modem_on_destroy(pjmedia_port *port);
void modem_at_init();
int modem_get_msg(void *user_data, uint8_t *msg, int max_len);
void modem_put_msg(void *user_data, const uint8_t *msg, int len);
int modem_modqueue_isready();
void modem_modqueue_append(uint8_t *buf, int len);
static int modem_at_control(void *user_data, int op, const char *num);
static void modem_log_supported_modulations(data_modems_state_t *s,
		int modulation_schemes);
static void modem_v8_handler(void *user_data, v8_parms_t *result);
static void spandsp_message_handler(void *user_data, int level,
		const char *text);

