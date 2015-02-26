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

#include "sipmodem.h"

#define THIS_FILE				"serial.c"
#define CMD_ESCAPE_CHAR			43
#define CMD_ESCAPE_CONFIRM		13
#define CMD_ESCAPE_LEN			3

void serial_init(const char *device_name, int baudrate) {
	enum sp_return status;

	sp_get_port_by_name(device_name, &sipmodem.sp_port);
	status = sp_open(sipmodem.sp_port, SP_MODE_READ_WRITE);
	if (status != SP_OK) {
		sp_free_port(sipmodem.sp_port);
		printf("Failure opening serial port %s\n", device_name);
		exit(1);
	}

	sp_flush(sipmodem.sp_port, SP_BUF_BOTH);
	sp_set_baudrate(sipmodem.sp_port, baudrate);
	sp_set_bits(sipmodem.sp_port, 8);
	sp_set_parity(sipmodem.sp_port, 0);
	sp_set_stopbits(sipmodem.sp_port, 1);
	sp_set_dtr(sipmodem.sp_port, SP_DTR_OFF);

	PJ_LOG(1, (THIS_FILE, "Using serial port %s", device_name));
}

void serial_write(void *user_data, uint8_t *buf, int len) {
	sp_nonblocking_write(sipmodem.sp_port, buf, len);
}

void serial_read_loop() {
	int i, readlen, free, escape_seq_count = CMD_ESCAPE_LEN;
	uint8_t readbuf[1024];
	enum sp_return status;
	enum sp_signal signal_mask;

	do {
		free = 1024;
		if (sipmodem.at_state->at_rx_mode == AT_MODE_CONNECTED)
			free = modem_modqueue_isready();
		sp_get_signals(sipmodem.sp_port, &signal_mask);
		if ((signal_mask & SP_SIG_DSR) && !sipmodem.sp_dsr_state) {
			PJ_LOG(3, (THIS_FILE, "DSR high"));
			sipmodem.sp_dsr_state = 1;
		} else if (!(signal_mask & SP_SIG_DSR) && sipmodem.sp_dsr_state) {
			PJ_LOG(3, (THIS_FILE, "DSR low"));
			sipmodem.sp_dsr_state = 0;
			// If connected, wait 5 seconds, then drop the call
			if (sipmodem.at_state->at_rx_mode == AT_MODE_CONNECTED) {
				sleep(5);
				sip_hangup(sipmodem.call_id);
			} else {
				// Wait for DSR to go high
				sleep(1);
			}
			continue;
		}
		if (free > 0) {
			readlen = sp_blocking_read(sipmodem.sp_port, readbuf, free, 100);
			if (readlen < 0)
				break;
			if (sipmodem.at_state->at_rx_mode == AT_MODE_CONNECTED) {
				for (i = 0; i < readlen; i++) {
					if (readbuf[i] == CMD_ESCAPE_CHAR
							&& escape_seq_count <= CMD_ESCAPE_LEN
							&& escape_seq_count > 0) {
						PJ_LOG(3,
								(THIS_FILE, "Escape sequence - %i bytes remaining", escape_seq_count));
						escape_seq_count--;
					} else if ((readbuf[i] == CMD_ESCAPE_CONFIRM
							&& escape_seq_count == 0)) {
						// Escape sequence triggered
						PJ_LOG(3, (THIS_FILE, "Entering command mode"));
						escape_seq_count = CMD_ESCAPE_LEN;
						at_set_at_rx_mode(sipmodem.at_state,
								AT_MODE_OFFHOOK_COMMAND);
						at_put_response_code(sipmodem.at_state,
								AT_RESPONSE_CODE_OK);
					} else if ((readbuf[i] != CMD_ESCAPE_CHAR
							&& escape_seq_count < CMD_ESCAPE_LEN)
							|| escape_seq_count < 0) {
						PJ_LOG(3, (THIS_FILE, "Resetting escape sequence"));
						escape_seq_count = CMD_ESCAPE_LEN;
					}
				}
				if (escape_seq_count == CMD_ESCAPE_LEN && readlen > 0)
					modem_modqueue_append(readbuf, readlen);
			} else
				at_interpreter(sipmodem.at_state, readbuf, readlen);
		}
	} while (sipmodem.on);
}

