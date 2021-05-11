/*
 *  Homeplug AV Ethernet frame definitions
 *
 *  Copyright (C) 2007-2012 Xavier Carcelle <xavier.carcelle@gmail.com>
 *		    	    Florian Fainelli <florian@openwrt.org>
 *			    Nicolas Thill <nico@openwrt.org>
 *
 *  The BSD License
 *  ===============
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *  3. Neither the name of OpenLink Software Inc. nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL OPENLINK OR
 *  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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

#ifndef __HOMEPLUG_AV_H__
#define __HOMEPLUG_AV_H__

#include <sys/types.h>
#include "faifa_compat.h"

#define ETHERTYPE_HOMEPLUG_AV  0x88e1

#define HPAV_VERSION_1_0       0x00
#define HPAV_VERSION_1_1       0x01

#define HPAV_MM_TYPE_MASK      0x0003
#define HPAV_MM_REQUEST        0x0000
#define HPAV_MM_CONFIRM        0x0001
#define HPAV_MM_INDICATE       0x0002
#define HPAV_MM_RESPONSE       0x0003

#define HPAV_MM_CATEGORY_MASK  0xE000
#define HPAV_MM_STA_TO_CCO     0x0000
#define HPAV_MM_ANY_TO_PCO     0x2000
#define HPAV_MM_CCO_TO_CCO     0x4000
#define HPAV_MM_STA_TO_STA     0x6000
#define HPAV_MM_MANUF_SPEC     0x8000
#define HPAV_MM_VENDOR_SPEC    0xA000

#define HPAV_MIN_FRAMSIZ       46

/*qca specific MMTYPE */
#define HPAV_MMTYPE_MS_PB_ENC 0x8001
#define HPAV_MMTYPE_MS_ADC_CAP 0x8004
#define HPAV_MMTYPE_MS_DISCOVER 0x8008

#define HPAV_MMTYPE_CC_DISC_LIST_REQ	0x0014
#define HPAV_MMTYPE_CC_DISC_LIST_CNF	0x0015
#define HPAV_MMTYPE_CM_ENC_PLD_IND	0x6004
#define HPAV_MMTYPE_CM_ENC_PLD_RSP	0x6005
#define HPAV_MMTYPE_CM_SET_KEY_REQ	0x6008
#define HPAV_MMTYPE_CM_SET_KEY_CNF	0x6009
#define HPAV_MMTYPE_CM_GET_KEY_REQ	0x600C
#define HPAV_MMTYPE_CM_GET_KEY_CNF	0x600D
#define HPAV_MMTYPE_CM_BRG_INFO_REQ	0x6020
#define HPAV_MMTYPE_CM_BRG_INFO_CNF	0x6021
#define HPAV_MMTYPE_CM_NW_INFO_REQ	0x6038
#define HPAV_MMTYPE_CM_NW_INFO_CNF	0x6039
#define HPAV_MMTYPE_CM_MME_ERROR_IND	0x6046
#define HPAV_MMTYPE_CM_NW_STATS_REQ	0x6048
#define HPAV_MMTYPE_CM_NW_STATS_CNF	0x6049
#define HPAV_MMTYPE_GET_SW_REQ		0xA000
#define HPAV_MMTYPE_GET_SW_CNF		0xA001
#define HPAV_MMTYPE_WR_MEM_REQ		0xA004
#define HPAV_MMTYPE_WR_MEM_CNF		0xA005
#define HPAV_MMTYPE_RD_MEM_REQ		0xA008
#define HPAV_MMTYPE_RD_MEM_CNF		0xA009
#define HPAV_MMTYPE_ST_MAC_REQ		0xA00C
#define HPAV_MMTYPE_ST_MAC_CNF		0xA00D
#define HPAV_MMTYPE_GET_NVM_REQ		0xA010
#define HPAV_MMTYPE_GET_NVM_CNF		0xA011
#define HPAV_MMTYPE_RS_DEV_REQ		0xA01C
#define HPAV_MMTYPE_RS_DEV_CNF		0xA01D
#define HPAV_MMTYPE_WR_MOD_REQ		0xA020
#define HPAV_MMTYPE_WR_MOD_CNF		0xA021
#define HPAV_MMTYPE_WR_MOD_IND		0xA022
#define HPAV_MMTYPE_RD_MOD_REQ		0xA024
#define HPAV_MMTYPE_RD_MOD_CNF		0xA025
#define HPAV_MMTYPE_NVM_MOD_REQ		0xA028
#define HPAV_MMTYPE_NVM_MOD_CNF		0xA029
#define HPAV_MMTYPE_WD_RPT_REQ		0xA02C
#define HPAV_MMTYPE_WD_RPT_IND		0xA02E
#define HPAV_MMTYPE_LNK_STATS_REQ	0xA030
#define HPAV_MMTYPE_LNK_STATS_CNF	0xA031
#define HPAV_MMTYPE_SNIFFER_REQ		0xA034
#define HPAV_MMTYPE_SNIFFER_CNF		0xA035
#define HPAV_MMTYPE_SNIFFER_IND		0xA036
#define HPAV_MMTYPE_NW_INFO_REQ		0xA038
#define HPAV_MMTYPE_NW_INFO_CNF		0xA039
#define HPAV_MMTYPE_CP_RPT_REQ		0xA040
#define HPAV_MMTYPE_CP_RPT_IND		0xA042
#define HPAV_MMTYPE_FR_LBK_REQ		0xA048
#define HPAV_MMTYPE_FR_LBK_CNF		0xA049
#define HPAV_MMTYPE_LBK_STAT_REQ		0xA04C
#define HPAV_MMTYPE_LBK_STAT_CNF		0xA04D
#define HPAV_MMTYPE_SET_KEY_REQ		0xA050
#define HPAV_MMTYPE_SET_KEY_CNF		0xA051
#define HPAV_MMTYPE_MFG_STRING_REQ	0xA054
#define HPAV_MMTYPE_MFG_STRING_CNF	0xA055
#define HPAV_MMTYPE_RD_CBLOCK_REQ	0xA058
#define HPAV_MMTYPE_RD_CBLOCK_CNF	0xA059
#define HPAV_MMTYPE_SET_SDRAM_REQ	0xA05C
#define HPAV_MMTYPE_SET_SDRAM_CNF	0xA05D
#define HPAV_MMTYPE_HOST_ACTION_IND	0xA062
#define HPAV_MMTYPE_HOST_ACTION_RSP	0xA063
#define HPAV_MMTYPE_OP_ATTR_REQ		0xA068
#define HPAV_MMTYPE_OP_ATTR_CNF		0xA069
#define HPAV_MMTYPE_GET_ENET_PHY_REQ	0xA06C
#define HPAV_MMTYPE_GET_ENET_PHY_CNF	0xA06D
#define HPAV_MMTYPE_TONE_MAP_REQ		0xA070
#define HPAV_MMTYPE_TONE_MAP_CNF		0xA071

/**
 * hpav_frame_header - HomePlug AV frame header
 * @mmver:		MM version of the frame
 * @mmtype:		MM type for this frame
 */
struct hpav_frame_header {
	u_int8_t	mmver;
	u_int16_t	mmtype;
} __attribute__((__packed__));

/**
 * hpav_frame_public_payload - HomePlug AV Public MMEs payload
 * @data:		Frame-Specific data
 */
struct hpav_frame_public_payload {
	u_int8_t	frag_count:4;
	u_int8_t	frag_index:4;
	u_int8_t	frag_seqnum;
	u_int8_t	data[0];
} __attribute__((__packed__));

/**
 * hpav_frame_vendor_payload - HomePlug AV Vendor-Specific MMEs payload
 * @oui:		Vendor OUI (Intellon OUI : 0x00, 0xb0, 0x52)
 * @data:		Frame-Specific data
 */
struct hpav_frame_vendor_payload {
	u_int8_t	oui[3];
	u_int8_t	data[0];
} __attribute__((__packed__));

/**
 * hpav_frame - HomePlug AV frame
 * @header:	hpav_frame_header
 * @public	Public variant part
 * @vendor	Vendor-Specific variant part
 */
struct hpav_frame {
	struct hpav_frame_header header;
	union {
		struct hpav_frame_public_payload pub;
		struct hpav_frame_vendor_payload vendor;
	} __attribute__((__packed__)) payload;
} __attribute__((__packed__));

/**
 * hpav_frame_ops - Homeplug AV ethernet frames operations
 * @mmtype:		frame specific MM type
 * @desc:		frame description
 * @init_frame:		frame specific initialisation callback
 * @dump_frame:		frame specific dump callback
 */
struct hpav_frame_ops {
	u_int16_t	mmtype;
	char 		*desc;
	int		(*init_frame)(void *buf, int len, void *user);
	int		(*dump_frame)(void *buf, int len, struct ether_header *hdr);
};

/* Central Coordination Discover List MME */

struct cc_sta_info {
	u_int8_t	macaddr[6];
	u_int8_t	tei;
	u_int8_t	same_network;
	u_int8_t	snid;
	u_int8_t	rsvd;
	u_int8_t	cco_cap;
	u_int8_t	sig_level;
} __attribute__((__packed__));

struct cc_sta_infos {
	u_int8_t		count;
	struct cc_sta_info	infos[0];
} __attribute__((__packed__));

struct cc_net_info {
	u_int8_t	nid[7];
	u_int8_t	snid;
	u_int8_t	hybrid_mode;
	u_int8_t	num_bcn_slots;
	u_int8_t	cco_status;
	u_int16_t	bcn_offset;
} __attribute__((__packed__));

struct cc_net_infos {
	u_int8_t		count;
	struct cc_net_info	infos[0];
} __attribute__((__packed__));

/* 0014 - CC Discover List Request */

/* 0015 - CC Discover List Confirm */
struct cc_discover_list_confirm {
	struct cc_sta_infos sta[0];
	struct cc_net_infos net[0];
} __attribute__((__packed__));

/* Get Device/SW Version MME */

/* 0xA000 - Get Device/SW Version Request */

/* 0xA001 - Get Device/SW Version Confirm */
struct get_device_sw_version_confirm {
	u_int8_t	mstatus;
	u_int8_t	device_id;
	u_int8_t	version_length;
	u_int8_t	version[64];
	u_int8_t	upgradeable;
} __attribute__((__packed__));

#define INT6000_DEVICE_ID	0x1
#define INT6300_DEVICE_ID	0x2
#define INT6400_DEVICE_ID	0x3

/* Write MAC Memory MME */

/* A004 - Write MAC Memory Request */
struct write_mac_memory_request {
	u_int32_t	address;
	u_int32_t	length;
	u_int8_t	data[0];
} __attribute__((__packed__));

/* A005 - Write MAC Memory Confirm */
struct write_mac_memory_confirm {
	u_int8_t	mstatus;
	u_int32_t	address;
	u_int32_t	length;
} __attribute__((__packed__));


/* Read MAC Memory MME */

/* A008 - Read MAC Memory Request */
struct read_mac_memory_request {
	u_int32_t	address;
	u_int32_t	length;
} __attribute__((__packed__));

/* A009 - Read MAC Memory Confirm */
struct read_mac_memory_confirm {
	u_int8_t	mstatus;
	u_int32_t	address;
	u_int32_t	length;
	u_int8_t	data[0];
} __attribute__((__packed__));


/* Start MAC MME */

/* Module ID */
enum module_id {
	MAC_SL_IMG	= 0x00,
	MAC_SW_IMG	= 0x01,
	PIB		= 0x02,
	WR_ALT_FLSH	= 0x10,
} __attribute__((__packed__));

/* A00C - Start MAC Request */
struct start_mac_request {
	u_int8_t	module_id;
	u_int8_t	reserved1[3];
	u_int32_t	image_load;
	u_int32_t	image_length;
	u_int32_t	image_chksum;
	u_int32_t	image_saddr;
} __attribute__((__packed__));

/* A00D - Start MAC Confirm */
struct start_mac_confirm {
	u_int8_t	mstatus;
	u_int8_t	module_id;
} __attribute__((__packed__));


/* Get NVM Parameters MME */

/* A010 - Get NVM Parameters Request */

/* A011 - Get NVM Parameters Confirm */
struct get_nvm_parameters_confirm {
	u_int8_t	mstatus;
	u_int32_t	manuf_code;
	u_int32_t	page_size;
	u_int32_t	block_size;
	u_int32_t	mem_size;
} __attribute__((__packed__));


/* Reset Device MME */

/* A01C - Reset Device Request */

/* A01D - Reset Device Confirm */
struct reset_device_confirm {
	u_int8_t	mstatus;
} __attribute__((__packed__));


/* Write Module Data MME */

enum write_module_id {
	SUCCESS		= 0x00,
	INV_MOD_ID	= 0x10,
	BAD_HDR_CHKSUM	= 0x18,
	INV_LEN		= 0x1C,
	UNEX_OFF	= 0x20,
	INV_CHKSUM	= 0x14,
} __attribute__((__packed__));

/* A020 - Write Module Data Request */
struct write_mod_data_request {
	u_int8_t	module_id;
	u_int8_t	reserved1[1];
	u_int16_t	length;
	u_int32_t	offset;
	u_int32_t	checksum;
	u_int8_t	data[0];
} __attribute__((__packed__));

/* A021 - Write Module Data Confirm */
struct write_mod_data_confirm {
	u_int8_t	mstatus;
	u_int8_t	module_id;
	u_int8_t	reserved1[1];
	u_int16_t	length;
	u_int32_t	offset;
} __attribute__((__packed__));

/* A022 - Write Module Data Indicate */
struct write_mod_data_indicate {
	u_int8_t	mstatus;
	u_int8_t	module_id;
} __attribute__((__packed__));


/* Read Module Data MME */

/* A024 - Read Module Data Request */
struct read_mod_data_request {
	u_int8_t	module_id;
	u_int8_t	reserved1[1];
	u_int16_t	length;
	u_int32_t	offset;
} __attribute__((__packed__));

/* A025 - Read Module Data Confirm */
struct read_mod_data_confirm {
	u_int8_t	mstatus;
	u_int8_t	reserved1[3];
	u_int8_t	module_id;
	u_int8_t	reserved2[1];
	u_int16_t	length;
	u_int32_t	offset;
	u_int32_t	checksum;
	u_int8_t	data[0];
} __attribute__((__packed__));


/* Write Module Data to NVM MME */

/* A028 - Write Module Data to NVM Request */
struct write_module_data_to_nvm_request {
	u_int8_t	module_id;
} __attribute__((__packed__));

/* A029 - Write Module Data to NVM Confirm */
struct write_module_data_to_nvm_confirm {
	u_int8_t	mstatus;
	u_int8_t	module_id;
} __attribute__((__packed__));


/* Get Watchdog Report MME */

/* A02C - Get Watchdog Report Request */
struct get_watchdog_report_request {
	u_int16_t	session_id;
	u_int8_t	clr_flag;
} __attribute__((__packed__));

/* A02E - Get Watchdog Report Indicate */
struct get_watchdog_report_indicate {
	u_int8_t	mstatus;
	u_int16_t	session_id;
	u_int8_t	num_parts;
	u_int8_t	cur_part;
	u_int16_t	data_length;
	u_int8_t	data_offset;
	u_int8_t	data[0];
} __attribute__((__packed__));


/* Link Statistics MME */

/* Status types */
enum statistics_status {
	HPAV_SUC	= 0x00,
	HPAV_INV_CTL	= 0x01,
	HPAV_INV_DIR	= 0x02,
	HPAV_INV_LID	= 0x10,
	HPAV_INV_MAC	= 0x20,
};

/* Direction types */
enum statistics_direction {
	HPAV_SD_TX	= 0x00,
	HPAV_SD_RX	= 0x01,
	HPAV_SD_BOTH	= 0x02,
};

enum link_id {
	HPAV_LID_CSMA_CAP_0	= 0x00,
	HPAV_LID_CSMA_CAP_1	= 0x01,
	HPAV_LID_CSMA_CAP_2	= 0x02,
	HPAV_LID_CSMA_CAP_3	= 0x03,
	HPAV_LID_CSMA_SUM 	= 0xF8,
	HPAV_LID_CSMA_SUM_ANY	= 0xFC,
};

struct rx_interval_stats {
	u_int8_t	phyrate;
	u_int64_t	pb_passed;
	u_int64_t	pb_failed;
	u_int64_t	tbe_passed;
	u_int64_t	tbe_failed;
} __attribute__((__packed__));

struct tx_link_stats {
	u_int64_t	mpdu_ack;
	u_int64_t	mpdu_coll;
	u_int64_t	mpdu_fail;
	u_int64_t	pb_passed;
	u_int64_t	pb_failed;
} __attribute__((__packed__));

struct rx_link_stats {
	u_int64_t	mpdu_ack;
	u_int64_t	mpdu_fail;
	u_int64_t	pb_passed;
	u_int64_t	pb_failed;
	u_int64_t	tbe_passed;
	u_int64_t	tbe_failed;
	u_int8_t	num_rx_intervals;
	struct rx_interval_stats	rx_interval_stats[0];
} __attribute__((__packed__));

/* A030 - Link Statistics Request */
struct link_statistics_request {
	u_int8_t	control;
	u_int8_t	direction;
	u_int8_t	link_id;
	u_int8_t	macaddr[6];
} __attribute__((__packed__));

/* A031 - Link Statistics Confirm */
struct link_statistics_confirm {
	u_int8_t	mstatus;
	u_int8_t	direction;
	u_int8_t	link_id;
	u_int8_t	tei;
	union {
		struct tx_link_stats tx;
		struct rx_link_stats rx;
		struct {
			struct tx_link_stats tx;
			struct rx_link_stats rx;
		} __attribute__((__packed__)) both;
	} __attribute__((__packed__));
} __attribute__((__packed__));


/* Sniffer MME */

/* Sniffer Control */
enum sniffer_control {
	HPAV_SC_DISABLE		= 0x00,
	HPAV_SC_ENABLE		= 0x01,
	HPAV_SC_NO_CHANGE	= 0x02,
};

enum sniffer_state {
	HPAV_ST_DISABLED	= 0x00,
	HPAV_ST_ENABLED		= 0x01,
};

struct hpav_fc {
	u_int8_t	del_type:3;
	u_int8_t	access:1;
	u_int8_t	snid:4;
	u_int8_t	stei;
	u_int8_t	dtei;
	u_int8_t	lid;
	u_int8_t	cfs:1;
	u_int8_t	bdf:1;
	u_int8_t	hp10df:1;
	u_int8_t	hp11df:1;
	u_int8_t	eks:4;
	u_int8_t	ppb;
	u_int8_t	ble;
	u_int8_t	pbsz:1;
	u_int8_t	num_sym:2;
	u_int8_t	tmi_av:5;
	u_int16_t	fl_av:12;
	u_int8_t	mpdu_cnt:2;
	u_int8_t	burst_cnt:2;
	u_int8_t	clst:3;
	u_int8_t	rg_len_lo:5;
	u_int8_t	rg_len_hi:1;
	u_int8_t	mfs_cmd_mgmt:3;
	u_int8_t	mfs_cmd_data:3;
	u_int8_t	rsr:1;
	u_int8_t	mcf:1;
	u_int8_t	dccpcf:1;
	u_int8_t	mnbf:1;
	u_int8_t	rsvd:5;
	u_int8_t	fccs_av[3];
} __attribute__((__packed__));

struct hpav_bcn {
	u_int8_t	del_type:3;
	u_int8_t	access:1;
	u_int8_t	snid:4;
	u_int32_t	bts;
	u_int16_t	bto_0;
	u_int16_t	bto_1;
	u_int16_t	bto_2;
	u_int16_t	bto_3;
	u_int8_t	fccs_av[3];
} __attribute__((__packed__));

/* 0xA034 - Sniffer Request */
struct sniffer_request {
	u_int8_t	control;
	u_int8_t	reserved1[4];
} __attribute__((__packed__));

/* 0xA035 - Sniffer Confirm */
struct sniffer_confirm {
	u_int8_t	mstatus;
	u_int8_t	state;
	u_int8_t	da[6];
} __attribute__((__packed__));

/* 0xA036 - Sniffer Indicate */
struct sniffer_indicate {
	u_int8_t	type;
	u_int8_t	direction;
	u_int64_t	systime;
	u_int32_t	beacontime;
	struct hpav_fc	fc;
	struct hpav_bcn	bcn;
} __attribute__((__packed__));


/* Network Info MME */

enum sta_role {
	HPAV_SR_STA	= 0x00,
	HPAV_SR_PROXY	= 0x01,
	HPAV_SR_CCO	= 0x02,
};

struct sta_info {
	u_int8_t	sta_macaddr[6];
	u_int8_t	sta_tei;
	u_int8_t	bridge_macaddr[6];
	u_int8_t	avg_phy_tx_rate;
	u_int8_t	avg_phy_rx_rate;
} __attribute__((__packed__));

/* 0xA038 - Network Info Request */

/* 0xA039 - Network Info Confirm */
struct network_info_confirm {
	u_int8_t	num_avlns;
	u_int8_t	nid[7];
	u_int8_t	snid;
	u_int8_t	tei;
	u_int8_t	sta_role;
	u_int8_t	cco_macaddr[6];
	u_int8_t	cco_tei;
	u_int8_t	num_stas;
	struct sta_info	stas[0];
} __attribute__((__packed__));


/* Check Points MME */

/* A040 - Check Points Request */
struct check_points_request {
	u_int16_t	session_id;
	u_int8_t	clr_flag;
} __attribute__((__packed__));

/* A042 - Check Points Indicate */
struct check_points_indicate {
	u_int8_t	mstatus:3;
	u_int8_t	major:1;
	u_int8_t	buf_locked:1;
	u_int8_t	auto_lock:1;
	u_int8_t	unsoc_upd:1;
	u_int8_t	unsoc:1;
	u_int8_t	reserved1[14];
	u_int16_t	session_id;
	u_int32_t	length;
	u_int32_t	offset;
	u_int32_t	index;
	u_int8_t	num_parts;
	u_int8_t	cur_part;
	u_int16_t	data_length;
	u_int16_t	data_offset;
	u_int8_t	data[0];
} __attribute__((__packed__));


/* Loopback MME */

/* A048 - Loopback Request */
struct loopback_request {
	u_int8_t	duration;
	u_int8_t	reserved1[0];
	u_int16_t	length;
	u_int8_t	data[0];
} __attribute__((__packed__));

/* A049 - Loopback Confirm */
struct loopback_confirm {
	u_int8_t	mstatus;
	u_int8_t	duration;
	u_int16_t	length;
} __attribute__((__packed__));


/* Loopback Status MME */

/* A04C - Loopback Status Request */

/* A04D - Loopback Status Confirm */
struct loopback_status_confirm {
	u_int8_t	mstatus;
	u_int8_t	state;
} __attribute__((__packed__));


/* Set Encryption Key MME */

enum set_enc_key_status {
	KEY_SUCCESS	= 0x00,
	KEY_INV_EKS	= 0x10,
	KEY_INV_PKS	= 0x11,
	KEY_UKN		= 0x12,
};

#define AES_KEY_SIZE	16

/* A050 - Set Encryption Key Request */
struct set_encryption_key_request {
	u_int8_t	peks;
	u_int8_t	nmk[AES_KEY_SIZE];
	u_int8_t	peks_payload;
	u_int8_t	rdra[6];
	u_int8_t	dak[AES_KEY_SIZE];
} __attribute__((__packed__));

/* A051 - Set Encryption Key Confirm */
struct set_encryption_key_confirm {
	u_int8_t	mstatus;
};


/* Get Manufacturing String MME */

/* A054 - Get Manufacturing String Request */

/* A055 - Get Manufacturing String Confirm */
struct get_manuf_string_confirm {
	u_int8_t	status;
	u_int8_t	length;
	u_int8_t	data[64];
} __attribute__((__packed__));


/* Read Configuration Block & SDRAM Configuration MME */

enum sdram_status {
	SDR_INV_CHKSUM	= 0x30,
	SDR_BIST_FAILED	= 0x34,
};

struct sdram_config {
	u_int32_t	size;
	u_int32_t	conf_reg;
	u_int32_t	timing0;
	u_int32_t	timing1;
	u_int32_t	ctl_reg;
	u_int32_t	ref_reg;
	u_int32_t	clk_reg_val;
	u_int32_t	reserved;
} __attribute__ ((__packed__));

struct block_header {
	u_int32_t	version;
	u_int32_t	img_rom_addr;
	u_int32_t	img_sdram_addr;
	u_int32_t	img_length;
	u_int32_t	img_checksum;
	u_int32_t	entry_point;
	u_int8_t	reserved[12];
	u_int32_t	next_header;
	u_int32_t	hdr_checksum;
} __attribute__((__packed__));

/* A058 - Read Configuration Block Request */

/* A059 - Read Configuration Block Confirm */
struct read_config_block_confirm {
	u_int8_t		mstatus;
	u_int8_t		config_length;
	struct block_header 	hdr;
	struct sdram_config 	config;
} __attribute__((__packed__));

/* A05C - Set SDRAM Configuration Request */
struct set_sdram_config_request {
	struct sdram_config	config;
	u_int32_t		checksum;
} __attribute__((__packed__));

/* A05D - Set SDRAM Configuration Confirm */
struct set_sdram_config_confirm {
	u_int8_t	mstatus;
} __attribute__((__packed__));


/* Embedded Host Action Required MME */

enum host_actions {
	LOADER		= 0x00,
	FIRM_UP_RDY 	= 0x01,
	PIB_UP_RDY	= 0x02,
	FIRM_UP_PIB_RDY = 0x03,
	LOADER_SDR_RDY  = 0x04,
};

/* A062 - Embedded Host Action Required Indicate */
struct embedded_host_action_indicate {
	u_int8_t	action;
} __attribute__((__packed__));

/* A063 - Embedded Host Action Required Response */
struct embedded_host_action_response {
	u_int8_t	mstatus;
} __attribute__((__packed__));


/* Get Devices Attributes MME */

struct get_devices_attrs_fmt {
	u_int8_t	hardware[16];
	u_int8_t	software[16];
	u_int32_t	major;
	u_int32_t	minor;
	u_int32_t	subversion;
	u_int32_t	build_number;
	u_int8_t	rsvd[8];
	u_int8_t	build_date[8];
	u_int8_t	release_type[12];
} __attribute__((__packed__));

/* A068 - Get Devices Attributes Request */
struct get_devices_attrs_request {
	u_int32_t	cookie;
	u_int8_t	rtype;
} __attribute__((__packed__));

/* A069 - Get Devices Attributes Confirm */
struct get_devices_attrs_confirm {
	u_int16_t	status;
	u_int32_t	cookie;
	u_int8_t	rtype;
	u_int16_t	size;
	struct get_devices_attrs_fmt	fmt;
} __attribute__((__packed__));


/* Ethernet PHY Settings MME */

enum enet_speed {
	ENET	 = 0x00,
	FA_ENET	 = 0x01,
	GIG_ENET = 0x02,
};

/* AO6C - Get Ethernet PHY Settings Request */
struct get_enet_phy_settings_request {
	u_int8_t	mcontrol;
	u_int8_t	addcaps;
	u_int8_t	reserved[3];
} __attribute__((__packed__));

/* AO6D - Get Ethernet PHY Settings Confirm */
struct get_enet_phy_settings_confirm {
	u_int8_t	status;
	u_int8_t	speed;
	u_int8_t	duplex;
} __attribute__((__packed__));


/* Tone Map Characteristics MME */

/* Various carrier modulations */
enum mod_carrier {
	NO	= 0x0,
	BPSK	= 0x1,
	QPSK	= 0x2,
	QAM_8	= 0x3,
	QAM_16	= 0x4,
	QAM_64	= 0x5,
	QAM_256	= 0x6,
	QAM_1024 = 0x7,
};

struct modulation_stats {
	unsigned	no;
	unsigned	bpsk;
	unsigned	qpsk;
	unsigned	qam8;
	unsigned	qam16;
	unsigned	qam64;
	unsigned	qam256;
	unsigned	qam1024;
	unsigned	unknown;
};

/* Statistics group two carrier on 4 bits */
struct carrier {
	u_int8_t	mod_carrier_lo:4;
	u_int8_t	mod_carrier_hi:4;
} __attribute__((__packed__));

/* A070 - Tone Map Characteristics Request */
struct get_tone_map_charac_request {
	u_int8_t	macaddr[6];
	u_int8_t	tmslot;
} __attribute__((__packed__));

/* A071 - Tone Map Characteristics Confirm */
struct get_tone_map_charac_confirm {
	u_int8_t	mstatus;
	u_int8_t	tmslot;
	u_int8_t	num_tms;
	u_int16_t	tm_num_act_carrier;
	struct carrier	carriers[0];
} __attribute__((__packed__));


/* Encrypted Payload MME */

enum peks_val {
	DST_STA_DAK	= 0x00,
	NMK_KNOWN_STA	= 0x01,
	ID_TEKS		= 0x02, /* to OxE */
	NO_KEY		= 0x0F,
};

enum avln_status {
	UN_ASSOC_LVL_0	= 0x00,
	UN_ASSOC_LVL_1	= 0x01,
	UN_ASSOC_LVL_2	= 0x02,
	UN_ASSOC_LVL_3	= 0x03,
	UN_ASSOC_NPCO	= 0x04,
	UN_ASSOC_PCO	= 0x05,
	CCO_AVLN	= 0x08,
};

enum pid {
	AUTH_REQ_NEW	= 0x00,
	PROV_STA_NEW	= 0x01,
	PROV_STA_DAK	= 0x02,
	PROV_STA_UKE	= 0x03,
	HLE_PROTO	= 0x04,
};

struct cm_enc_payload_mm {
	u_int16_t	len;
	u_int8_t	mme[0];
} __attribute__((__packed__));

struct cm_enc_payload_hle_payload {
	u_int16_t	len;
	u_int8_t	random_filler[0];
	u_int8_t	payload;
	u_int32_t	crc;
	u_int8_t	pid;
	u_int8_t	prn;
	u_int8_t	pmn;
	u_int8_t	padding[0];
	u_int8_t	rf_len[0];
} __attribute__((__packed__));

/* 6004 - Encrypted Payload Indicate */
struct cm_enc_payload_indicate {
	u_int8_t	peks;
	u_int8_t	avln_status;
	u_int8_t	pid;
	u_int8_t	prn;
	u_int8_t	pmn;
	u_int8_t	aes_iv_uuid[AES_KEY_SIZE];
	union {
		struct cm_enc_payload_mm mm;
		struct cm_enc_payload_hle_payload payload;
	} __attribute__((__packed__));
} __attribute__((__packed__));

/* 6005 - Encrypted Payload Response */
struct cm_enc_payload_response {
	u_int8_t	result;
	u_int8_t	pid;
	u_int16_t	prn;
} __attribute__((__packed__));


/* Set Key MME */

enum key_type {
	DAK_AES_128	= 0x00,
	NMK_AES_128	= 0x01,
	NEK_AES_128	= 0x02,
	TEK_AES_128	= 0x03,
	HASH_KEY	= 0x04,
	NONCE_ONLY	= 0x05,
};

/* 6008 - Set Key Request */
struct cm_set_key_request {
	u_int8_t	key_type;
	u_int32_t	my_nonce;
	u_int32_t	your_nonce;
	u_int8_t	pid;
	u_int16_t	prn;
	u_int8_t	pmn;
	u_int8_t	cco_cap;
	u_int8_t	nid[7];
	u_int8_t	new_eks;
	u_int8_t	new_key[0]; /* or AES_KEY_SIZE */
} __attribute__((__packed__));

/* 6009 - Set Key Confirm */
struct cm_set_key_confirm {
	u_int8_t	result;
	u_int32_t	my_nonce;
	u_int32_t	your_nonce;
	u_int8_t	pid;
	u_int16_t	prn;
	u_int8_t	pmn;
	u_int8_t	cco_cap;
} __attribute__((__packed__));


/* Get Key MME */

/* 600C - Get Key Request */
struct cm_get_key_request {
	u_int8_t	req_type;
	u_int8_t	req_key_type;
	u_int8_t	nid[7];
	u_int32_t	my_nonce;
	u_int8_t	pid;
	u_int16_t	prn;
	u_int8_t	pmn;
	u_int8_t	hash_key[0];
} __attribute__((__packed__));

/* 600D - Get Key Confirm */
struct cm_get_key_confirm {
	u_int8_t	result;
	u_int8_t	req_key_type;
	u_int32_t	my_nonce;
	u_int32_t	your_nonce;
	u_int8_t	nid[7];
	u_int8_t	eks;
	u_int8_t	pid;
	u_int16_t	prn;
	u_int8_t	pmn;
	u_int8_t	key[0];
} __attribute__((__packed__));


/* Get Bridge Infos MME */

struct bridge_infos {
	u_int8_t	btei;
	u_int8_t	nbda;
	u_int8_t	bri_addr[0][6];
};

/* 6020 - Get Bridge Infos Request */

/* 6021 - Get Bridge Infos Confirm */
struct cm_brigde_infos_confirm {
	u_int8_t	bsf;
	union {
		struct	bridge_infos bridge_infos;
	} __attribute__((__packed__));
} __attribute__((__packed__));


/* Get Network Infos MME */

struct cm_net_info {
	u_int8_t	nid[7];
	u_int8_t	snid;
	u_int8_t	tei;
	u_int8_t	sta_role;
	u_int8_t	macaddr[6];
	u_int8_t	access;
	u_int8_t	num_cord;
} __attribute__((__packed__));

struct cm_net_infos {
	u_int8_t		count;
	struct cm_net_info	infos[0];
} __attribute__((__packed__));

/* 6038 - Get Network Infos Request */

/* 6039 - Get Network Infos Confirm */
struct cm_get_network_infos_confirm {
	struct cm_net_infos	net;
} __attribute__((__packed__));

enum err_reason_code {
	MME_NOT_SUP		= 0,
	INVALID_MME_FIELDS	= 1,
	UNSUPPORTED_FEATURE	= 2,
};

/* 6046 - MME Error Indication */
struct cm_mme_error_ind {
	u_int8_t	err_reason_code;
	u_int8_t	rx_version;
	u_int16_t	rx_mmtype;
	u_int16_t	invalid_offset;
} __attribute__((__packed__));

/* Get Network Stats MME */

struct cm_sta_info {
	u_int8_t	macaddr[6];
	u_int8_t	avg_phy_dr_tx;
	u_int8_t	avg_phy_dr_rx;
} __attribute__((__packed__));

struct cm_sta_infos {
	u_int8_t		count;
	struct cm_sta_info	infos[0];
} __attribute__((__packed__));

/* 6048 - Get Network Stats Request */

/* 6049 - Get Network Stats Confirm */
struct cm_get_network_stats_confirm {
	struct cm_sta_infos	sta;
} __attribute__((__packed__));

#endif /* __HOMEPLUG_AV_H__ */
