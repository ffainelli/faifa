/*
 *  Homeplug 1.0 Ethernet frame definitions
 *
 *  Copyright (C) 2007-2008 Xavier Carcelle <xavier.carcelle@gmail.com>
 *		    	    Florian Fainelli <florian@openwrt.org>
 *			    Nicolas Thill <nico@openwrt.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

/*
 *  In addition, as a special exception, the copyright holders give
 *  permission to link the code of portions of this program with the
 *  OpenSSL library under certain conditions as described in each
 *  individual source file, and distribute linked combinations
 *  including the two.
 *  You must obey the GNU General Public License in all respects
 *  for all of the code used other than OpenSSL.  If you modify
 *  file(s) with this exception, you may extend this exception to your
 *  version of the file(s), but you are not obligated to do so.  If you
 *  do not wish to do so, delete this exception statement from your
 *  version.  If you delete this exception statement from all source
 *  files in the program, then also delete it here.
 */

#ifndef __HOMEPLUG_H__
#define __HOMEPLUG_H__

#include <sys/types.h>

#define ETHERTYPE_HOMEPLUG     0x887b


/**
 * hp10_mmentry - HomePlug 1.0 MAC Management Entry (MME)
 * @mmetype:	MME type
 * @mmelength:	MME data length
 * @mmedata:	MME data
 */
struct hp10_mmentry {
	u_int8_t	mmetype:5;
	u_int8_t	mmeversion:3;
	u_int8_t	mmelength;
	u_int8_t	mmedata[0];
} __attribute__((__packed__));

/**
 * hp10_frame - HomePlug 1.0 frame
 * @mecount:	Number of MAC entries in this frame
 * @mentries:	MAC Entries
 */
struct hp10_frame {
	u_int8_t      mmecount:7;
	u_int8_t      reserved:1;
	struct hp10_mmentry mmentries[0];
} __attribute__((__packed__));

/**
 * hp10_frame_ops - Homeplug 1.0 ethernet frames operations
 * @mmtype:		frame specific MM type
 * @desc:		frame description
 * @init_frame:		frame specific initialisation callback
 * @dump_frame:		frame specific dump callback
 */
struct hp10_frame_ops {
	u_int8_t	mmtype;
	char 		*desc;
	int		(*init_frame)(void *buf, int len, void *user);
	int		(*dump_frame)(void *buf, int len);
};


/* 00 - Channel Estimation Request */
struct hp10_channel_estimation_request {
	u_int8_t	reserved1:4;
	u_int8_t	version:4;
} __attribute__((__packed__));

/* 08 - Network parameters Confirm */
struct hp10_parameters_stats_confirm {
	u_int16_t	tx_ack_cnt;
	u_int16_t	tx_nack_cnt;
	u_int16_t	tx_fail_cnt;
	u_int16_t	tx_cont_loss_cnt;
	u_int16_t	tx_coll_cnt;
	u_int16_t	tx_ca3_cnt;
	u_int16_t	tx_ca2_cnt;
	u_int16_t	tx_ca1_cnt;
	u_int16_t	tx_ca0_cnt;
	u_int32_t	rx_cumul;
} __attribute__((__packed__));

/* 1a - Network statistics Confirm */
struct hp10_tonemap {
	u_int8_t	netw_da[6];
	u_int16_t	bytes40;
	u_int16_t	fails;
	u_int16_t	drops;
} __attribute__((__packed__));

#define HP10_NUM_TONE_MAP	15

/* 1c - Extended network statistics Confirm */
struct hp10_network_stats_confirm {
	u_int8_t	icid:7;
	u_int8_t	ac:1;
  	u_int16_t	bytes40_robo;
  	u_int16_t	fails_robo;
  	u_int16_t	drops_robo;
	struct hp10_tonemap	nstone[HP10_NUM_TONE_MAP];
} __attribute__((__packed__));

/* 1f - Performance statistics confirm */
struct hp10_perf_stats_confirm {
	u_int8_t	rsvd:7;
	u_int8_t	perf_ctrl:1;
	u_int16_t	max_delay;
	u_int16_t	max_delay_jitter_ca[4];
	u_int16_t	max_latency_ca[4];
	u_int16_t	max_latency_bin_ca0[10];
	u_int16_t	max_latency_bin_ca1[10];
	u_int16_t	max_latency_bin_ca2[10];
	u_int16_t	max_latency_bin_ca3[10];
	u_int16_t	rst_cnt;
	u_int16_t	txack; // [31 - 16]
	u_int16_t	txnack; // [31 - 16]
	u_int16_t	txcoll; // [31 - 16]
	u_int16_t	tcloss; // [31 - 16]
	u_int16_t	txcalat[4]; // [31 - 16]
	u_int16_t	rxbp40; //[63 - 32]
} __attribute__((__packed__));

#endif /* __INTELLON_H__ */
