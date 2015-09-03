/*
 *  Homeplug 1.0/AV Ethernet frame handling and operations
 *
 *  Copyright (C) 2007-2008 Xavier Carcelle <xavier.carcelle@gmail.com>
 *		    	    Florian Fainelli <florian@openwrt.org>
 *			    Nicolas Thill <nico@openwrt.org>
 *
 *	Modifications by Andrew Margolis (c) 2015 to produce human-readable MPDU frame 
 *	control fields and Beacon MPDU payload fields in accordance with the IEEE 
 *   1901-2010 Powerline standard.
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

#include <arpa/inet.h>
#include <sys/types.h>
#ifndef __CYGWIN__
#include <net/ethernet.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <inttypes.h>

#include "faifa.h"
#include "faifa_compat.h"
#include "faifa_priv.h"
#include "frame.h"

#include "homeplug.h"
#include "homeplug_av.h"

#include "crypto.h"
#include "endian.h"
#include "crypto.h"
#include "crc32.h"

FILE *err_stream;
FILE *out_stream;
FILE *in_stream;

/* Constants */
static u_int8_t hpav_intellon_oui[3] = { 0x00, 0xB0, 0x52};
static u_int8_t hpav_intellon_macaddr[ETHER_ADDR_LEN] = { 0x00, 0xB0, 0x52, 0x00, 0x00, 0x01 };
static u_int8_t broadcast_macaddr[ETHER_ADDR_LEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

/**
 * init_hex - initialize a buffer using hexadecimal parsing (%2hx)
 * @buf:	buffer to initialize
 * @len:	length of the buffer (sizeof(buf))
 */
static int init_hex(void *buf, int len)
{
	int avail = len;
	u_int8_t *p = buf;

	while (avail > 0) {
		if (fscanf(in_stream, "%2hx", (short unsigned int *)p) <= 0)
			break;
		p++;
		avail--;
	}

	return (len - avail);
}

/**
 * dump_hex - dump a buffer using the hexadecimal conversion (%02hX)
 * @buf:	buffer to dump the content
 * @len:	length of the buffer (sizeof(buf))
 * @sep:	optional separator, defaults to empty
 */
int dump_hex(void *buf, int len, char *sep)
{
	int avail = len;
	u_int8_t *p = buf;

	while (avail > 0) {
		faifa_printf(out_stream, "%02hX%s", *p, (avail > 1) ? sep : "");
		p++;
		avail--;
	}

	return len;
}

#define HEX_BLOB_BYTES_PER_ROW  16

static u_int32_t dump_hex_blob(faifa_t *UNUSED(faifa), u_int8_t *buf, u_int32_t len)
{
	u_int32_t i, d, m = len % HEX_BLOB_BYTES_PER_ROW;

	faifa_printf(out_stream, "Binary Data, %lu bytes", (unsigned long int)len);
	for (i = 0; i < len; i += HEX_BLOB_BYTES_PER_ROW) {
		d = (len - i) / HEX_BLOB_BYTES_PER_ROW;
		faifa_printf(out_stream, "\n%08lu: ", (unsigned long int)i);
		dump_hex((u_int8_t *)buf + i, (d > 0) ? HEX_BLOB_BYTES_PER_ROW : m, " ");
	}
	faifa_printf(out_stream, "\n");

	return len;
}

/**
 * init_empty_frame - do nothing to a frame
 * @buf:	unused
 * @len:	unused
 */
static int init_empty_frame(void *UNUSED(buf), int UNUSED(len), void *UNUSED(user))
{
	return 0;
}

/*
 * The following functions are not documented and are faifa internal
 * operations. They should never be called from outside do_frame or
 * do_receive_frame because the of generic buffer handling.
 *
 * These functions are called as generic callbacks to a corresponding
 * request, confirmation, indication or response.
 */

static int hpav_init_write_mac_memory_request(void *buf, int len, void *UNUSED(buffer))
{
	int avail = len;
	struct write_mac_memory_request *mm = buf;

	faifa_printf(out_stream, "Address? ");
	fscanf(in_stream, "%8x", &(mm->address));
	faifa_printf(out_stream, "Length? ");
	fscanf(in_stream, "%8x", &(mm->length));
	avail -= sizeof(*mm);
	faifa_printf(out_stream, "Data?\n");
	avail -= init_hex(mm->data, mm->length);

	return (len - avail);
}

static const char *int6x00_device_id_str(u_int8_t device_id)
{
	switch (device_id) {
	case INT6000_DEVICE_ID:
		return "INT6000";
	case INT6300_DEVICE_ID:
		return "INT6300";
	case INT6400_DEVICE_ID:
		return "INT6400";
	default:
		return "Unknown";
	}
}

static int hpav_dump_get_device_sw_version_confirm(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	struct get_device_sw_version_confirm *mm = buf;

	faifa_printf(out_stream, "Status: %s\n", mm->mstatus ? "Failure" : "Success");
	faifa_printf(out_stream, "Device ID: %s, Version: %s, upgradeable: %hhd\n",
		int6x00_device_id_str(mm->device_id),
		(char *)(mm->version), mm->upgradeable);
	avail -= sizeof(*mm);

	return (len - avail);
}

static int hpav_dump_write_mac_memory_request(void *buf, int len,  struct ether_header *UNUSED(hdr))
{
	int avail = len;
	struct write_mac_memory_request *mm = buf;

	faifa_printf(out_stream, "Address: 0x%08x\n", mm->address);
	faifa_printf(out_stream, "Length: 0x%08x\n", mm->length);
	avail -= sizeof(*mm);
	faifa_printf(out_stream, "Data: ");
	avail -= dump_hex(mm->data, mm->length, " ");
	faifa_printf(out_stream, "\n");

	return (len - avail);
}

static int hpav_dump_write_mac_memory_confirm(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	struct write_mac_memory_confirm *mm = buf;

	switch (mm->mstatus) {
	case 0x00:
		faifa_printf(out_stream, "Status: Succes\n");
		break;
	case 0x10:
		faifa_printf(out_stream, "Status: Invalid address\n");
		goto out;
		break;
	case 0x14:
		faifa_printf(out_stream, "Status: Invalid length\n");
		goto out;
		break;
	}
	faifa_printf(out_stream, "Address: 0x%08x\n", mm->address);
	faifa_printf(out_stream, "Length: 0x%08x\n", mm->length);
out:
	avail -= sizeof(*mm);

	return (len - avail);
}

static int hpav_init_read_mac_memory_request(void *buf, int len, void *UNUSED(buffer))
{
	int avail = len;
	struct read_mac_memory_request *mm = buf;

	faifa_printf(out_stream, "Address? ");
	fscanf(in_stream, "%8x", &(mm->address));
	faifa_printf(out_stream, "Length? ");
	fscanf(in_stream, "%8x", &(mm->length));
	avail -= sizeof(*mm);

	return (len - avail);
}

static int hpav_dump_read_mac_memory_request(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	struct read_mac_memory_confirm *mm = buf;

	faifa_printf(out_stream, "Address: 0x%08x\n", mm->address);
	faifa_printf(out_stream, "Length: %u (0x%08x)\n", mm->length, mm->length);
	avail -= sizeof(*mm);

	return (len - avail);
}

static int hpav_dump_read_mac_memory_confirm(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	struct read_mac_memory_confirm *mm = buf;

	switch (mm->mstatus) {
	case 0x00:
		faifa_printf(out_stream, "Status: Succes\n");
		break;
	case 0x10:
		faifa_printf(out_stream, "Status: Invalid address\n");
		goto out;
		break;
	case 0x14:
		faifa_printf(out_stream, "Status: Invalid length\n");
		goto out;
		break;
	}
	faifa_printf(out_stream, "Address: 0x%08x\n", mm->address);
	faifa_printf(out_stream, "Length: %u (0x%08x)\n", mm->length, mm->length);
	faifa_printf(out_stream, "Data: ");
	avail -= dump_hex(mm->data, mm->length, " ");
	faifa_printf(out_stream, "\n");
out:
	avail -= sizeof(*mm);

	return (len - avail);
}

static const char *get_signal_level_str(u_int8_t sig_level)
{
	switch (sig_level) {
	case 0x00:
		return "N/A";
	case 0x01:
		return "> - 10 dB, but <= 0 dB";
	case 0x02:
		return "> - 15 dB, but <= -10 dB";
	case 0x03:
		return "> - 20 dB, but <= -15 dB";
	case 0x04:
		return "> - 25 dB, but <= -20 dB";
	case 0x05:
		return "> - 30 dB, but <= -25 dB";
	case 0x06:
		return "> - 35 dB, but <= -30 dB";
	case 0x07:
		return "> - 40 dB, but <= -35 dB";
	case 0x08:
		return "> - 45 dB, but <= -40 dB";
	case 0x09:
		return "> - 50 dB, but <= -45 dB";
	case 0x0A:
		return "> - 55 dB, but <= -50 dB";
	case 0x0B:
		return "> - 60 dB, but <= -55 dB";
	case 0x0C:
		return "> - 65 dB, but <= -60 dB";
	case 0x0D:
		return "> - 70 dB, but <= -65 dB";
	case 0x0E:
		return "> - 75 dB, but <= -70 dB";
	case 0x0F:
		return "<= -75 dB";
	default:
		return "Unknown";
	}

	return NULL;
}

static void dump_cc_sta_info(struct cc_sta_info *sta_info)
{
	faifa_printf(out_stream, "MAC address: ");
	dump_hex(sta_info->macaddr, ETHER_ADDR_LEN, ":");
	faifa_printf(out_stream, "\n");
	faifa_printf(out_stream, "TEI: %d\n", sta_info->tei);
	faifa_printf(out_stream, "Same network: %s\n", sta_info->same_network ? "Yes" : "No");
	faifa_printf(out_stream, "SNID: %d\n", sta_info->snid);
	faifa_printf(out_stream, "CCo caps: %02hhx\n", sta_info->cco_cap);
	faifa_printf(out_stream, "Signal Level: %s\n", get_signal_level_str(sta_info->sig_level));
}

static const char *get_cco_status_str(u_int8_t status)
{
	switch (status) {
	case 0x00:
		return "Unknown";
	case 0x01:
		return "Non-Coordinating network";
	case 0x02:
		return "Coordinating, group status unknown";
	case 0x03:
		return "Coordinating network, same group as CCo";
	case 0x04:
		return "Coordinating network, not same group as CCo";
	default:
		return "Unknown";
	}

	return NULL;
}

static void dump_cc_net_info(struct cc_net_info *net_info)
{
	faifa_printf(out_stream, "Network ID: "); dump_hex(net_info->nid, sizeof(net_info->nid), " "); faifa_printf(out_stream, "\n");
	faifa_printf(out_stream, "SNID: %d\n", net_info->snid);
	faifa_printf(out_stream, "Hybrid mode: %d\n", net_info->hybrid_mode);
	faifa_printf(out_stream, "Number of BCN slots: %d\n", net_info->num_bcn_slots);
	faifa_printf(out_stream, "CCo status: %s\n", get_cco_status_str(net_info->cco_status));
	faifa_printf(out_stream, "Beacon offset: %04hx\n", net_info->bcn_offset);
}

static int hpav_dump_cc_discover_list_confirm(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	struct cc_discover_list_confirm *mm = buf;
	struct cc_sta_infos *sta = (struct cc_sta_infos *)&(mm->sta);
	struct cc_net_infos *net = (struct cc_net_infos *)&(sta->infos[sta->count]);
	int i;

	faifa_printf(out_stream, "Number of Stations: %d\n", sta->count);
	avail -= sizeof(*sta);
	for (i = 0; i < sta->count; i++) {
		dump_cc_sta_info(&(sta->infos[i]));
		avail -= sizeof(sta->infos[i]);
	}

	faifa_printf(out_stream, "Number of Networks: %d\n", net->count);
	avail -= sizeof(*net);
	for (i = 0; i < net->count; i++) {
		dump_cc_net_info(&(net->infos[i]));
		avail -= sizeof(net->infos[i]);
	}

	return (len - avail);
}

static int hpav_init_start_mac_request(void *buf, int len, void *UNUSED(buffer))
{
	int avail = len;
	struct start_mac_request *mm = buf;

	faifa_printf(out_stream, "Module ID? ");
	fscanf(in_stream, "%2hhx", &(mm->module_id));
	faifa_printf(out_stream, "Image load address? ");
	fscanf(in_stream, "%8x", &(mm->image_load));
	faifa_printf(out_stream, "Image length? ");
	fscanf(in_stream, "%8x", &(mm->image_length));
	faifa_printf(out_stream, "Image checksum? ");
	fscanf(in_stream, "%8x", &(mm->image_chksum));
	faifa_printf(out_stream, "Image start address? ");
	fscanf(in_stream, "%8x", &(mm->image_saddr));
	avail -= sizeof(*mm);

	return (len - avail);
}

static int hpav_dump_start_mac_request(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	struct start_mac_request *mm = buf;

	faifa_printf(out_stream, "Module ID: %02hhx\n", mm->module_id);
	faifa_printf(out_stream, "Image load address: %08x\n", mm->image_load);
	faifa_printf(out_stream, "Image length: %u (0x%08x)\n", mm->image_length, mm->image_length);
	faifa_printf(out_stream, "Image checksum: %08x\n", mm->image_chksum);
	faifa_printf(out_stream, "Image start address: %08x\n", mm->image_saddr);
	avail -= sizeof(*mm);

	return (len - avail);
}

static int hpav_dump_start_mac_confirm(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	struct start_mac_confirm *mm = buf;

	switch (mm->mstatus) {
	case 0x00:
		faifa_printf(out_stream, "Status: Success\n");
		break;
	case 0x10:
		faifa_printf(out_stream, "Status: Invalid module ID\n");
		goto out;
		break;
	case 0x14:
		faifa_printf(out_stream, "Status: NVM not present\n");
		goto out;
		break;
	case 0x18:
		faifa_printf(out_stream, "Status: NVM too small\n");
		goto out;
		break;
	case 0x1C:
		faifa_printf(out_stream, "Status: Invalid header checksum\n");
		goto out;
		break;
	case 0x20:
		faifa_printf(out_stream, "Status: Invalid section checksum\n");
		goto out;
		break;
	}
	faifa_printf(out_stream, "Module ID: %02hhx\n", mm->module_id);
out:
	avail -= sizeof(*mm);

	return (len - avail);
}

static int hpav_dump_nvram_params_confirm(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	struct get_nvm_parameters_confirm *mm = buf;

	faifa_printf(out_stream, "Status: %s\n", mm->mstatus ? "NVRAM not present" : "Success");
	faifa_printf(out_stream, "Manufacturer code: %08x\n", mm->manuf_code);
	faifa_printf(out_stream, "Page size: %u (0x%08x)\n", mm->page_size, mm->page_size);
	faifa_printf(out_stream, "Block size: %u (0x%08x)\n", mm->block_size, mm->block_size);
	faifa_printf(out_stream, "Memory size: %u (0x%08x)\n", mm->mem_size, mm->mem_size);
	avail -= sizeof(*mm);

	return (len - avail);
}

static int hpav_dump_reset_device_confirm(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	struct reset_device_confirm *mm = buf;

	faifa_printf(out_stream, "Status : %s\n", mm->mstatus ? "Failure" : "Success");
	avail -= sizeof(*mm);

	return (len - avail);
}

static int hpav_init_write_data_request(void *buf, int len, void *UNUSED(buffer))
{
	int avail = len;
	struct write_mod_data_request *mm = buf;
	char filename[256];
	char *buffer;
	FILE *fp;
	short unsigned int size;
	uint32_t crc32;

	faifa_printf(out_stream, "Module ID? ");
	fscanf(in_stream, "%2hhx", &(mm->module_id));
	faifa_printf(out_stream, "Offset? ");
	fscanf(in_stream, "%8x", &(mm->offset));
	faifa_printf(out_stream, "Firmware file? ");
	fscanf(in_stream, "%s", (char *)filename);
	fp = fopen(filename, "rb");
	if (!fp) {
		faifa_printf(err_stream, "Cannot open: %s\n", filename);
		avail = -1;
		goto out;
	}
	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	if (size > 1024) {
		faifa_printf(out_stream, "Invalid file size > 1024\n");
		avail = -1;
		goto out;
	}
	fseek(fp, 0, SEEK_SET);
	mm->length = size;
	buffer = malloc(size);
	if (!buffer) {
		faifa_printf(err_stream, "Cannot allocate memory\n");
		avail = -1;
		goto out;
	}
	fread(buffer, size, 1, fp);
	/* Compute crc on the file */
	crc32 = crc32buf(buffer, size);
	memcpy(&(mm->data), buffer, size);
	mm->checksum = crc32;
out:
	if (fp)
		fclose(fp);
	avail -= sizeof(*mm);
	return (len - avail);
}

static int hpav_dump_write_mod_data_confirm(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	struct write_mod_data_confirm *mm =(struct write_mod_data_confirm *)buf;

	switch((short unsigned int)(mm->module_id)) {
	case SUCCESS:
		faifa_printf(out_stream, "Status: Success\n");
		break;
	case INV_MOD_ID:
		faifa_printf(out_stream, "Status: Invalid module ID\n");
		return (len - avail);
		break;
	case BAD_HDR_CHKSUM:
		faifa_printf(out_stream, "Status: Bad header checksum\n");
		return (len - avail);
		break;
	case INV_LEN:
		faifa_printf(out_stream, "Status: Invalid length\n");
		return (len - avail);
		break;
	case UNEX_OFF:
		faifa_printf(out_stream, "Status: Unexpected offset\n");
		return (len - avail);
		break;
	case INV_CHKSUM:
		faifa_printf(out_stream, "Status: Invalid checksum\n");
		return (len - avail);
		break;
	default:
		break;
	}
	faifa_printf(out_stream, "Length: %d\n", mm->length);
	faifa_printf(out_stream, "Offset: %08x\n", mm->offset);
	avail -= sizeof(*mm);

	return (len - avail);
}

static int hpav_init_read_mod_data_request(void *buf, int len, void *UNUSED(buffer))
{
	int avail = len;
	struct read_mod_data_request *mm = buf;

	faifa_printf(out_stream, "Module ID? ");
	fscanf(in_stream, "%2hhx", &(mm->module_id));
	faifa_printf(out_stream, "Length? ");
	fscanf(in_stream, "%hu", &(mm->length));
	faifa_printf(out_stream, "Offset? ");
	fscanf(in_stream, "%u", &(mm->offset));

	avail -= sizeof(*mm);
	return (len - avail);
}

static int hpav_dump_read_mod_data_confirm(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	struct read_mod_data_confirm *mm = buf;

	faifa_printf(out_stream, "Status: %s\n", mm->mstatus ? "Failure" : "Success");
	faifa_printf(out_stream, "Module ID: 0x%02hhx\n", mm->module_id);
	faifa_printf(out_stream, "Length: %d\n", mm->length);
	faifa_printf(out_stream, "Offset: 0x%08x\n", mm->offset);
	faifa_printf(out_stream, "Checksum: 0x%08x\n", mm->checksum);
	faifa_printf(out_stream, "Data:\n");
	dump_hex(mm->data + mm->offset, (unsigned int)(mm->length), " ");

	avail -= sizeof(*mm);

	return (len - avail);
}

static int hpav_dump_get_manuf_string_confirm(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	struct get_manuf_string_confirm *mm = buf;

	faifa_printf(out_stream, "Status: %s\n", mm->status ? "Failure" : "Success");
	faifa_printf(out_stream, "Length: %hhd (0x%02hhx)\n", mm->length, mm->length);
	faifa_printf(out_stream, "Manufacturer string: %s\n", (char *)(mm->data));
	avail -= sizeof(*mm);

	return (len - avail);
}

static void dump_conf_block(struct block_header *hdr)
{
	faifa_printf(out_stream, "Version: %08x\n", hdr->version);
	faifa_printf(out_stream, "Image address in NVRAM: 0x%08x\n", hdr->img_rom_addr);
	faifa_printf(out_stream, "Image address in SDRAM: 0x%08x\n", hdr->img_sdram_addr);
	faifa_printf(out_stream, "Image length: %u (0x%08x)\n", hdr->img_length, hdr->img_length);
	faifa_printf(out_stream, "Image checksum: %08x\n", hdr->img_checksum);
	faifa_printf(out_stream, "Image SDRAM entry point: 0x%08x\n", hdr->entry_point);
	faifa_printf(out_stream, "Address of next header: 0x%08x\n", hdr->next_header);
	faifa_printf(out_stream, "Header checksum: 0x%08x\n", hdr->hdr_checksum);
}

static void dump_sdram_block(struct sdram_config *config)
{
	faifa_printf(out_stream, "Size : %u (0x%08x)\n", config->size, config->size);
	faifa_printf(out_stream, "Configuration reg: 0x%08x\n", config->conf_reg);
	faifa_printf(out_stream, "Timing reg0: 0x%08x\n", config->timing0);
	faifa_printf(out_stream, "Timing reg1: 0x%08x\n", config->timing1);
	faifa_printf(out_stream, "Control reg: 0x%08x\n", config->ctl_reg);
	faifa_printf(out_stream, "Refresh reg: 0x%08x\n", config->ref_reg);
	faifa_printf(out_stream, "MAC clock reg : %u (0x%08x)\n", config->clk_reg_val, config->clk_reg_val);
}

static int hpav_dump_read_config_block_confirm(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	struct read_config_block_confirm *mm = buf;

	switch (mm->mstatus) {
	case 0x00:
		faifa_printf(out_stream, "Status: Success\n");
		break;
	case 0x01:
		faifa_printf(out_stream, "Status: Failure\n");
		goto out;
		break;
	case 0x10:
		faifa_printf(out_stream, "Status: No flash\n");
		goto out;
		break;
	}
	faifa_printf(out_stream, "Config length: %d\n", mm->config_length);
	dump_conf_block(&(mm->hdr));
	dump_sdram_block(&(mm->config));
out:
	avail -= sizeof(*mm);

	return (len - avail);
}

static int hpav_dump_set_sdram_config_confirm(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	short unsigned int *status = (short unsigned int *)buf;

	switch (*status) {
	case SUCCESS:
		faifa_printf(out_stream, "Status: Success\n");
		break;
	case SDR_INV_CHKSUM:
		faifa_printf(out_stream, "Status: Invalid checksum\n");
		break;
	case SDR_BIST_FAILED:
		faifa_printf(out_stream, "Status: BIST failed\n");
		break;
	default:
		break;
	}
	avail -= sizeof(*status);

	return (len - avail);
}

static int hpav_init_get_devices_attrs_request(void *buf, int len, void *UNUSED(buffer))
{
	int avail = len;
	struct get_devices_attrs_request *mm = buf;

	/* Generate a random number for the cookie */
	srand(getpid());
	mm->cookie = (long unsigned int)(random());

	avail -= sizeof(*mm);

	return (len - avail);
}

static int hpav_dump_get_devices_attrs_confirm(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	struct get_devices_attrs_confirm *mm = buf;

	switch (mm->status) {
	case 0x00:
		faifa_printf(out_stream, "Status: Success\n");
		break;
	case 0x01:
		faifa_printf(out_stream, "Status: Failure\n");
		goto out;
		break;
	case 0x02:
		faifa_printf(out_stream, "Status: Not supported\n");
		goto out;
		break;
	}
	faifa_printf(out_stream, "Cookie: %u\n", mm->cookie);
	faifa_printf(out_stream, "Report type: %s\n", mm->rtype ? "XML" : "Binary");
	faifa_printf(out_stream, "Size: %d\n", mm->size);
	faifa_printf(out_stream, "Hardware: %s\n", mm->fmt.hardware);
	faifa_printf(out_stream, "Software: %s\n", mm->fmt.software);
	faifa_printf(out_stream, "Major: %u\n", mm->fmt.major);
	faifa_printf(out_stream, "Minor: %u\n", mm->fmt.minor);
	faifa_printf(out_stream, "Subversion: %u\n", mm->fmt.subversion);
	faifa_printf(out_stream, "Build number: %u\n", mm->fmt.build_number);
	faifa_printf(out_stream, "Build date: %s\n", mm->fmt.build_date);
	faifa_printf(out_stream, "Release type: %s\n", mm->fmt.release_type);

out:
	avail -= sizeof(*mm);

	return (len - avail);
}

static int hpav_init_get_enet_phy_settings_request(void *buf, int len, void *UNUSED(user))
{
	int avail = len;
	struct get_enet_phy_settings_request *mm = buf;

	avail -= sizeof(*mm);

	return (len - avail);
}

static int hpav_dump_get_enet_phy_settings_confirm(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	struct get_enet_phy_settings_confirm *mm = buf;

	faifa_printf(out_stream, "Status: %s\n", mm->status ? "Failure" : "Success");
	switch(mm->speed) {
	case ENET:
		faifa_printf(out_stream, "Speed: Ethernet (10Mbits)\n");
		break;
	case FA_ENET:
		faifa_printf(out_stream, "Speed: Fast Ethernet (100Mbits)\n");
		break;
	case GIG_ENET:
		faifa_printf(out_stream, "Speed : Gigabit Ethernet (1Gbits)\n");
		break;
	}
	faifa_printf(out_stream, "Duplex: %s\n", mm->duplex ? "Full duplex" : "Half duplex");
	avail -= sizeof(*mm);

	return (len - avail);
}

static int hpav_init_get_tone_map_charac_request(void *buf, int len, void *UNUSED(user))
{
	int avail = len;
	u_int8_t macaddr[ETHER_ADDR_LEN];
	struct get_tone_map_charac_request *mm = buf;

	faifa_printf(out_stream, "Address of peer node?\n");
	fscanf(in_stream, "%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
		&macaddr[0], &macaddr[1], &macaddr[2],
		&macaddr[3], &macaddr[4], &macaddr[5]);
	memcpy(mm->macaddr, macaddr, ETHER_ADDR_LEN);

	faifa_printf(out_stream, "Tone map slot?\n0 -> slot 0\n1 -> slot 1 ...\n");
	fscanf(in_stream, "%2hhx", &(mm->tmslot));
	avail -= sizeof(*mm);

	return (len - avail);
}

char *get_carrier_modulation_str(short unsigned int modulation, struct modulation_stats *stats)
{
	switch(modulation) {
	case NO:
		stats->no++;
		return "No";
	case BPSK:
		stats->bpsk++;
		return "BPSK";
	case QPSK:
		stats->qpsk++;
		return "QPSK";
	case QAM_8:
		stats->qam8++;
		return "QAM-8";
	case QAM_16:
		stats->qam16++;
		return "QAM-16";
	case QAM_64:
		stats->qam64++;
		return "QAM-64";
	case QAM_256:
		stats->qam256++;
		return "QAM-256";
	case QAM_1024:
		stats->qam1024++;
		return "QAM-1024";
	default:
		stats->unknown++;
		return "Unknown";
	}
}

static void dump_modulation_stats(struct modulation_stats *stats)
{
	unsigned sum = 0;

	sum = stats->no + stats->bpsk + stats->qpsk + stats->qam8 + stats->qam16 + stats->qam64 +
		stats->qam256 + stats->qam1024 + stats->unknown;

	faifa_printf(out_stream, "Number of carriers with NO modulation: %d (%f %%)\n", stats->no, (double)((stats->no * 100) / sum));
	faifa_printf(out_stream, "Number of carriers with BPSK modulation: %d (%f %%)\n", stats->bpsk, (double)((stats->bpsk * 100) / sum));
	faifa_printf(out_stream, "Number of carriers with QPSK modulation: %d (%f %%)\n", stats->qpsk, (double)((stats->qpsk * 100) / sum));
	faifa_printf(out_stream, "Number of carriers with QAM-8 modulation: %d (%f %%)\n", stats->qam8, (double)((stats->qam8 * 100) / sum));
	faifa_printf(out_stream, "Number of carriers with QAM-16 modulation: %d (%f %%)\n", stats->qam16, (double)((stats->qam16 * 100) / sum));
	faifa_printf(out_stream, "Number of carriers with QAM-64 modulation: %d (%f %%)\n", stats->qam64, (double)((stats->qam64 * 100) / sum));
	faifa_printf(out_stream, "Number of carriers with QAM-256 modulation: %d (%f %%)\n", stats->qam256, (double)((stats->qam256 * 100) / sum));
	faifa_printf(out_stream, "Number of carriers with QAM-1024 modulation: %d (%f %%)\n", stats->qam1024, (double)((stats->qam1024 * 100) / sum));
	faifa_printf(out_stream, "Number of carriers with Unknown/unused modulation: %d (%f %%)\n", stats->unknown, (double)((stats->unknown * 100) / sum));
	faifa_printf(out_stream, "Number of modulation: %d\n", sum);
}

static int hpav_dump_get_tone_map_charac_confirm(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	int i;
	struct get_tone_map_charac_confirm *mm = buf;
	struct modulation_stats stats;
	uint16_t max_carriers;

	switch (mm->mstatus) {
	case 0x00:
		faifa_printf(out_stream, "Status: Success\n");
		break;
	case 0x01:
		faifa_printf(out_stream, "Status: Unknown MAC address\n");
		goto out;
		break;
	case 0x02:
		faifa_printf(out_stream, "Status: unknown ToneMap slot\n");
		goto out;
		break;
	}
	faifa_printf(out_stream, "Tone map slot: %02hhd\n", mm->tmslot);
	faifa_printf(out_stream, "Number of tone map: %02hhd\n", mm->num_tms);
	faifa_printf(out_stream, "Tone map number of active carriers: %d\n", mm->tm_num_act_carrier);

	memset(&stats, 0, sizeof(stats));

	max_carriers = mm->tm_num_act_carrier / 2;
	if (mm->tm_num_act_carrier & 1)
		max_carriers += 1;

	for (i = 0; i < max_carriers; i++) {
		faifa_printf(out_stream, "Modulation for carrier: %d : %s\n", i, get_carrier_modulation_str(mm->carriers[i].mod_carrier_lo, &stats));
		faifa_printf(out_stream, "Modulation for carrier: %d : %s\n", i + 1, get_carrier_modulation_str(mm->carriers[i].mod_carrier_hi, &stats));
	}

	faifa_printf(out_stream, "Modulation statistics\n");
	dump_modulation_stats(&stats);
out:
	avail -= sizeof(*mm);

	return (len - avail);
}

static int hpav_init_watchdog_report_request(void *buf, int len, void *UNUSED(buffer))
{
	int avail = len;
	struct get_watchdog_report_request *mm = buf;

	srand(getpid());
	mm->session_id = (unsigned int)(random());

	avail -= sizeof(*mm);

	return (len - avail);
}


static int hpav_dump_watchdog_report_indicate(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	struct get_watchdog_report_indicate *mm = buf;

	faifa_printf(out_stream, "Status: %s\n", mm->mstatus ? "Failure" : "Success");
	faifa_printf(out_stream, "Session ID: %d\n", mm->session_id);
	faifa_printf(out_stream, "Number of parts: %d\n", mm->num_parts);
	faifa_printf(out_stream, "Current part: %d\n", mm->cur_part);
	faifa_printf(out_stream, "Data length: %d\n", mm->data_length);
	faifa_printf(out_stream, "Data offset: 0x%02hhx\n", mm->data_offset);
	avail -= sizeof(*mm);

	return (len - avail);
}

static int hpav_init_link_stats_request(void *buf, int len, void *UNUSED(user))
{
	int avail = len;
	struct link_statistics_request *mm = buf;
	u_int8_t link_id;
	u_int8_t macaddr[ETHER_ADDR_LEN];
	int direction;

	faifa_printf(out_stream, "Direction ?\n0: TX\n1: RX\n2: TX and RX\n");
	fscanf(in_stream, "%2d", &direction);

	if (direction >= 0 || direction <= 2)
		mm->direction = direction;

	faifa_printf(out_stream, "Link ID ?\n");

	fscanf(in_stream, "%2hhx", &link_id);
	switch(link_id) {
	case HPAV_LID_CSMA_CAP_0:
	case HPAV_LID_CSMA_CAP_1:
	case HPAV_LID_CSMA_CAP_2:
	case HPAV_LID_CSMA_CAP_3:
	case HPAV_LID_CSMA_SUM:
	case HPAV_LID_CSMA_SUM_ANY:
		mm->link_id = link_id;
		break;
	default:
		mm->link_id = HPAV_LID_CSMA_SUM;
		faifa_printf(err_stream, "Invalid Link ID selected, defaulting to all CSMA stats\n");
		break;
	}

	if (link_id != HPAV_LID_CSMA_SUM_ANY) {
		faifa_printf(out_stream, "Address of peer node?\n");
		fscanf(in_stream, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
			&macaddr[0], &macaddr[1], &macaddr[2],
			&macaddr[3], &macaddr[4], &macaddr[5]);
		memcpy(mm->macaddr, macaddr, ETHER_ADDR_LEN);
	}
	avail -= sizeof(*mm);

	return (len - avail);
}

static void dump_tx_link_stats(struct tx_link_stats *tx)
{
	faifa_printf(out_stream, "MPDU acked......................: %"SCNu64"\n", tx->mpdu_ack);
	faifa_printf(out_stream, "MPDU collisions.................: %"SCNu64"\n", tx->mpdu_coll);
	faifa_printf(out_stream, "MPDU failures...................: %"SCNu64"\n", tx->mpdu_fail);
	faifa_printf(out_stream, "PB transmitted successfully.....: %"SCNu64"\n", tx->pb_passed);
	faifa_printf(out_stream, "PB transmitted unsuccessfully...: %"SCNu64"\n", tx->pb_failed);
}

static void dump_rx_link_stats(struct rx_link_stats *rx)
{
	int i;

	faifa_printf(out_stream, "MPDU acked......................: %"SCNu64"\n", rx->mpdu_ack);
	faifa_printf(out_stream, "MPDU failures...................: %"SCNu64"\n", rx->mpdu_fail);
	faifa_printf(out_stream, "PB received successfully........: %"SCNu64"\n", rx->pb_passed);
	faifa_printf(out_stream, "PB received unsuccessfully......: %"SCNu64"\n", rx->pb_failed);
	faifa_printf(out_stream, "Turbo Bit Errors passed.........: %"SCNu64"\n", rx->tbe_passed);
	faifa_printf(out_stream, "Turbo Bit Errors failed.........: %"SCNu64"\n", rx->tbe_failed);

	for (i = 0; i < rx->num_rx_intervals; i++) {
		faifa_printf(out_stream, "-- Rx interval %d --\n", i);
		faifa_printf(out_stream, "Rx PHY rate.....................: %02hhd\n",
				rx->rx_interval_stats[i].phyrate);
		faifa_printf(out_stream, "PB received successfully........: %"SCNu64"n",
				rx->rx_interval_stats[i].pb_passed);
		faifa_printf(out_stream, "PB received failed..............: %"SCNu64"\n",
				rx->rx_interval_stats[i].pb_failed);
		faifa_printf(out_stream, "TBE errors over successfully....: %"SCNu64"\n",
				rx->rx_interval_stats[i].tbe_passed);
		faifa_printf(out_stream, "TBE errors over failed..........: %"SCNu64"\n",
				rx->rx_interval_stats[i].tbe_failed);
	}
}

static int hpav_dump_link_stats_confirm(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	struct link_statistics_confirm *mm = buf;

	switch(mm->mstatus) {
	case HPAV_SUC:
		faifa_printf(out_stream, "Status: Success\n");
		break;
	case HPAV_INV_CTL:
		faifa_printf(out_stream, "Status: Invalid control\n");
		goto out;
		break;
	case HPAV_INV_DIR:
		faifa_printf(out_stream, "Status: Invalid direction\n");
		goto out;
		break;
	case HPAV_INV_LID:
		faifa_printf(out_stream, "Status: Invalid Link ID\n");
		goto out;
		break;
	case HPAV_INV_MAC:
		faifa_printf(out_stream, "Status: Invalid MAC address\n");
		goto out;
		break;
	}

	faifa_printf(out_stream, "Link ID: %02hhx\n", mm->link_id);
	faifa_printf(out_stream, "TEI: %02hhx\n", mm->tei);

	switch (mm->direction) {
	case HPAV_SD_TX:
		faifa_printf(out_stream, "Direction: Tx\n");
		dump_tx_link_stats(&(mm->tx));
		break;
	case HPAV_SD_RX:
		faifa_printf(out_stream, "Direction: Rx\n");
		dump_rx_link_stats(&(mm->rx));
		break;
	case HPAV_SD_BOTH:
		faifa_printf(out_stream, "Direction: Tx\n");
		dump_tx_link_stats(&(mm->both.tx));
		faifa_printf(out_stream, "Direction: Rx\n");
		dump_rx_link_stats(&(mm->both.rx));
		break;
	default:
		break;
	}
out:
	avail -= sizeof(*mm);

	return (len - avail);
}


static const char *get_sniffer_control_str(int control)
{
	static const char *control_unknown = "unknown";
	static const char *controls[] = {
		[HPAV_SC_DISABLE] = "disable",
		[HPAV_SC_ENABLE] =  "enable",
		[HPAV_SC_NO_CHANGE] =  "no change",
	};

	if ((HPAV_SC_DISABLE <= control) && (control <= HPAV_SC_NO_CHANGE)) {
		return controls[control];
	}

	return control_unknown;
}

static int hpav_init_sniffer_request(void *buf, int len, void *UNUSED(buffer))
{
	int avail = len;
	struct sniffer_request *mm = buf;
	int control;

	faifa_printf(out_stream, "Sniffer mode?\n");
	for (control = HPAV_SC_DISABLE; control <= HPAV_SC_NO_CHANGE; control++) {
		faifa_printf(out_stream, "%d: %s\n", control, get_sniffer_control_str(control));
	}
	fscanf(in_stream, "%d", &control);
	switch(control) {
		case HPAV_SC_DISABLE:
		case HPAV_SC_ENABLE:
		case HPAV_SC_NO_CHANGE:
			mm->control = control;
			break;
		default:
			mm->control = HPAV_SC_NO_CHANGE;
			faifa_printf(err_stream, "Invalid sniffer mode selected, no change\n");
			break;
	}
	avail -= sizeof(*mm);

	return (len - avail);
}

static int hpav_dump_sniffer_request(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	struct sniffer_request *mm = buf;

	faifa_printf(out_stream, "Sniffer mode : 0x%02hhx (%s)\n", mm->control, get_sniffer_control_str(mm->control));
	avail -= sizeof(*mm);

	return (len - avail);
}

static const char *get_sniffer_state_str(int state)
{
	static const char *state_unknown = "unknown";
	static const char *states[] = {
		[HPAV_ST_DISABLED] = "disabled",
		[HPAV_ST_ENABLED] =  "enabled",
	};

	if ((HPAV_ST_DISABLED <= state) && (state <= HPAV_ST_ENABLED)) {
		return states[state];
	}
	return state_unknown;
}


static int hpav_dump_sniffer_confirm(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	struct sniffer_confirm *mm = buf;

	faifa_printf(out_stream, "Status: 0x%02hhx\n", mm->mstatus);
	faifa_printf(out_stream, "Sniffer State: 0x%02hhx (%s)\n", mm->state, get_sniffer_state_str(mm->state));
	avail -= sizeof(*mm);
	faifa_printf(out_stream, "Destination MAC Address: ");
	avail -= dump_hex(mm->da, sizeof(mm->da), ":");
	faifa_printf(out_stream, "\n");

	avail -= sizeof(*mm);

	return (len - avail);
}

/* The following six functions (c) Andrew Margolis were added or amended to make 
faifa conform better to IEEE 1901-2010 standard by decoding all delimiters properly.

The seventh added function was added to decode the important beacon MPDU payload.

See also additions and amendents to homeplug_av.h 
*/


/*
1. Function for decoding delimiter = start of frame - IEEE 1910-2010 Table 6-10
*/

static void dump_hpav_frame_ctl(struct hpav_fc *fc)
{
	faifa_printf (out_stream, "STEI: %u (0x0%02hx)\n", (short unsigned int)(fc->stei),(short unsigned int)(fc->stei));
	faifa_printf (out_stream, "DTEI: %u (0x0%02hx)\n", (short unsigned int)(fc->dtei),(short unsigned int)(fc->dtei));
	faifa_printf (out_stream, "Link ID: %u (0x0%02hx)\n", (short unsigned int)(fc->lid),(short unsigned int)(fc->lid));
	faifa_printf (out_stream, "Contention free session: %s\n", fc->cfs ? "Yes" : "No (CSMA)");
	faifa_printf (out_stream, "Beacon detected: %s\n", fc->bdf ? "Yes" : "No");
	faifa_printf (out_stream, "TIA-1113 Detected: %s\n", fc->hp10df ? "Yes" : "No");
	faifa_printf (out_stream, "1901-aware-TIA-1113 Detected: %s\n", fc->hp11df ? "Yes" : "No");
	faifa_printf (out_stream, "Encryption Key Select: %u (0x0%1hx) = ", (short unsigned int)(fc->eks),(short unsigned int)(fc->eks));
	faifa_printf (out_stream, "%s", (fc->eks & 8) ? "1" : "0");
	faifa_printf (out_stream, "%s", (fc->eks & 4) ? "1" : "0");
	faifa_printf (out_stream, "%s", (fc->eks & 2) ? "1" : "0");
	faifa_printf (out_stream, "%s\n", (fc->eks & 1) ? "1" : "0");
	faifa_printf (out_stream, "Pending PHY blocks: %u (0x0%02hx)\n", (short unsigned int)(fc->ppb),(short unsigned int)(fc->ppb));
	faifa_printf (out_stream, "Bit loading estimate: %u (0x0%02hx)\n", (short unsigned int)(fc->ble),(short unsigned int)(fc->ble));
	faifa_printf (out_stream, "PHY block size: %s octets\n", fc->pbsz ? "136" : "520");
	faifa_printf (out_stream, "Number of symbols: %u (0x0%1hx)\n", (short unsigned int)(fc->num_sym),(short unsigned int)(fc->num_sym));
	faifa_printf (out_stream, "1901 Tonemap index: %u (0x0%1hx)\n", (short unsigned int)(fc->tmi_av),(short unsigned int)(fc->tmi_av));
	faifa_printf (out_stream, "1901 frame length in multiples of 1.28 usec: %u (0x0%3hx) = ", fc->fl_av,fc->fl_av);
	if (fc->fl_av > 0x3d) 
		{
		faifa_printf (out_stream, "%g usec\n", ((float)(fc->fl_av*128/100)));
		}
	else
		{
		faifa_printf (out_stream, "Reserved\n");
		}
	faifa_printf (out_stream, "Count of MPDUs to follow: %u (0x0%1hx)\n", (short unsigned int)(fc->mpdu_cnt),(short unsigned int)(fc->mpdu_cnt));
	faifa_printf (out_stream, "Burst count: %u (0x0%1hx)\n", (short unsigned int)(fc->burst_cnt),(short unsigned int)(fc->burst_cnt));
	faifa_printf (out_stream, "Bidirectional Burst: %s after this MPDU\n", fc->bbf ? "Continue" : "Terminate");
	faifa_printf (out_stream, "Max Reverse Transmission Frame Length: %u (0x0%1hx)\n", (short unsigned int)(fc->mrtfl),(short unsigned int)(fc->mrtfl));
	faifa_printf (out_stream, "Different CP PHY Clock Flag: %s\n", fc->dcppcf ? "Yes" : "No");
	faifa_printf (out_stream, "Long MPDU multicast: %s\n", fc->mcf ? "Yes" : "No (unicast)");
	faifa_printf (out_stream, "Multi-network Broadcast: %s\n", fc->mnbf ? "Yes" : "No");
	faifa_printf (out_stream, "Request SACK Retransmission: %s\n", fc->rsr ? "Yes" : "No");
	faifa_printf (out_stream, "MAC SAP Type: %s\n", fc->mst ? "Reserved" : "Ethernet II");
	faifa_printf (out_stream, "Management MAC Frame Stream Command: %u (0x0%1hx)\n", (short unsigned int)(fc->mfs_cmd_mgmt),(short unsigned int)(fc->mfs_cmd_mgmt));
	faifa_printf (out_stream, "Data MAC Frame Stream Command: %u (0x0%1hx)\n", (short unsigned int)(fc->mfs_cmd_data),(short unsigned int)(fc->mfs_cmd_data));
	faifa_printf (out_stream, "Management MAC Frame Stream Response: %u (0x0%1hx)\n", (short unsigned int)(fc->mfs_rsp_mgmt),(short unsigned int)(fc->mfs_rsp_mgmt));
	faifa_printf (out_stream, "Data MAC Frame Stream Response: %u (0x0%1hx)\n", (short unsigned int)(fc->mfs_rsp_data),(short unsigned int)(fc->mfs_rsp_data));
	faifa_printf (out_stream, "Bit Map SACK: %u (0x0%1hx)\n", (short unsigned int)(fc->bm_sack1),(short unsigned int)(fc->bm_sack1));
	faifa_printf (out_stream, "Frame control check sequence: 0x0%2hx%2hx%2hx\n",
		(unsigned int)(fc->fccs_av[0]),
		(unsigned int)(fc->fccs_av[1]),
		(unsigned int)(fc->fccs_av[2]));
}

/*
2. Function for decoding delimiter = beacon - IEEE 1910-2010 Table 6-9
*/

void dump_hpav_beacon(struct hpav_bcn *bcn)
{
	faifa_printf (out_stream, "Beacon timestamp: %u (0x%08x)\n",
		bcn->bts, bcn->bts);
	faifa_printf (out_stream, "Beacon transmission offset 0: %d (0x%04hx)\n",
		bcn->bto_0, bcn->bto_0);
	faifa_printf (out_stream, "Beacon transmission offset 1: %d (0x%04hx)\n",
		bcn->bto_1, bcn->bto_1);
	faifa_printf (out_stream, "Beacon transmission offset 2: %d (0x%04hx)\n",
		bcn->bto_2, bcn->bto_2);
	faifa_printf (out_stream, "Beacon transmission offset 3: %d (0x%04hx)\n",
		bcn->bto_3, bcn->bto_3);
	faifa_printf (out_stream, "Frame control check sequence: 0x0%2hhx%2hhx%2hhx\n",
		bcn->fccs_av[0], bcn->fccs_av[1], bcn->fccs_av[2]);
}

/*
3. Function for decoding delimiter = sack - IEEE 1910-2010 Table 6-28
*/

void dump_hpav_sack(struct hpav_sack *sack)
{
	faifa_printf (out_stream, "DTEI: %u (0x0%02hx)\n", (short unsigned int)(sack->dtei),(short unsigned int)(sack->dtei));
	faifa_printf (out_stream, "Contention free session: %s\n", sack->cfs ? "Yes" : "No (CSMA)");
	faifa_printf (out_stream, "Beacon detected: %s\n", sack->bdf ? "Yes" : "No");
	faifa_printf (out_stream, "Sack version number: %s\n", sack->svn ? "1" : "0");
	faifa_printf (out_stream, "Request Reverse Transmission: %s\n", sack->rrtf ? "Requested" : "Not requested");
	faifa_printf (out_stream, "Data MAC Frame Stream Response: %u (0x0%1hx)\n", (short unsigned int)(sack->mfs_rsp_data),(short unsigned int)(sack->mfs_rsp_data));
	faifa_printf (out_stream, "Management MAC Frame Stream Response: %u (0x0%1hx)\n", (short unsigned int)(sack->mfs_rsp_mgmt),(short unsigned int)(sack->mfs_rsp_mgmt));
	faifa_printf (out_stream, "Frame control check sequence: 0x0%2hx%2hx%2hx\n",
		(unsigned int)(sack->fccs_av[0]),
		(unsigned int)(sack->fccs_av[1]),
		(unsigned int)(sack->fccs_av[2]));
}

/*
4. Function for decoding delimiter = RTS/CTS - IEEE 1910-2010 Table 6-37
*/

void dump_hpav_rtscts(struct hpav_rtscts *rtscts)
{
	faifa_printf (out_stream, "STEI: %u (0x0%02hx)\n", (short unsigned int)(rtscts->stei),(short unsigned int)(rtscts->stei));
	faifa_printf (out_stream, "DTEI: %u (0x0%02hx)\n", (short unsigned int)(rtscts->dtei),(short unsigned int)(rtscts->dtei));
	faifa_printf (out_stream, "Link ID: %u (0x0%02hx)\n", (short unsigned int)(rtscts->lid),(short unsigned int)(rtscts->lid));
	faifa_printf (out_stream, "Contention free session: %s\n", rtscts->cfs ? "Yes" : "No (CSMA)");
	faifa_printf (out_stream, "Beacon detected: %s\n", rtscts->bdf ? "Yes" : "No");
	faifa_printf (out_stream, "TIA-113 Detected: %s\n", rtscts->hp10df ? "Yes" : "No");
	faifa_printf (out_stream, "1901-aware-TIA-1113 Detected: %s\n", rtscts->hp11df ? "Yes" : "No");
	faifa_printf (out_stream, "RTS flag: %s MPDU\n", rtscts->rtsf ? "RTS" : "CTS");
	faifa_printf (out_stream, "Immediate Grant Flag: %s\n", rtscts->igf ? "Yes" : "No");
	faifa_printf (out_stream, "Multi-network Broadcast: %s\n", rtscts->mnbf ? "Yes" : "No");
	faifa_printf (out_stream, "Multicast: %s\n", rtscts->mcf ? "Yes" : "No");
	faifa_printf (out_stream, "Frame control check sequence: 0x0%2hx%2hx%2hx\n",
		(unsigned int)(rtscts->fccs_av[0]),
		(unsigned int)(rtscts->fccs_av[1]),
		(unsigned int)(rtscts->fccs_av[2]));
}

/*
5. Function for decoding delimiter = sound - IEEE 1910-2010 Table 6-40
*/

void dump_hpav_sound(struct hpav_sound *sound)
{
	faifa_printf (out_stream, "STEI: %u (0x0%02hx)\n", (short unsigned int)(sound->stei),(short unsigned int)(sound->stei));
	faifa_printf (out_stream, "DTEI: %u (0x0%02hx)\n", (short unsigned int)(sound->dtei),(short unsigned int)(sound->dtei));
	faifa_printf (out_stream, "Link ID: %u (0x0%02hx)\n", (short unsigned int)(sound->lid),(short unsigned int)(sound->lid));
	faifa_printf (out_stream, "Contention free session: %s\n", sound->cfs ? "Yes" : "No (CSMA)");
	faifa_printf (out_stream, "PHY block size: %s octets\n", sound->pbsz ? "136" : "520");
	faifa_printf (out_stream, "Beacon detected: %s\n", sound->bdf ? "Yes" : "No");
	faifa_printf (out_stream, "Sound Ack Flag: %s\n", sound->saf ? "Yes" : "No");
	faifa_printf (out_stream, "Sound Complete Flag: %s\n", sound->scf ? "Yes" : "No");
	faifa_printf (out_stream, "Tone Maps Requested: %u (0x0%02hx)\n", (short unsigned int)(sound->req_tm),(short unsigned int)(sound->req_tm));
	faifa_printf (out_stream, "1901 frame length in multiples of 1.28 usec: %u (0x0%3hx) = ", sound->fl_av,sound->fl_av);
	if (sound->fl_av > 0x3d) 
		{
		faifa_printf (out_stream, "%g usec\n", ((float)(sound->fl_av*128/100)));
		}
	else
		{
		faifa_printf (out_stream, "Reserved\n");
		}
	faifa_printf (out_stream, "MPDU count: %u (0x0%1hx)\n", (short unsigned int)(sound->mpducnt),(short unsigned int)(sound->mpducnt));
	faifa_printf (out_stream, "Pending PHY blocks: %u (0x0%02hx)\n", (short unsigned int)(sound->ppb),(short unsigned int)(sound->ppb));
	faifa_printf (out_stream, "Sound Reason Code: %u (0x0%02hx)\n", (short unsigned int)(sound->src),(short unsigned int)(sound->src));
	faifa_printf (out_stream, "Additional Tone Maps Requested: %u (0x0%02hx)\n", (short unsigned int)(sound->add_req_tm),(short unsigned int)(sound->add_req_tm));
	faifa_printf (out_stream, "Maximum PBs per symbol: %u (0x0%02hx)\n", (short unsigned int)(sound->max_pb_sym),(short unsigned int)(sound->max_pb_sym));
	faifa_printf (out_stream, "Extended Carriers Support Flag: %s\n", sound->ecsf ? "Yes" : "No");
	faifa_printf (out_stream, "Extended Carriers Used Flag: %s\n", sound->ecuf ? "Yes" : "No");
	faifa_printf (out_stream, "Extended Modulation Support: %u (0x0%1hx)\n", (short unsigned int)(sound->ems),(short unsigned int)(sound->ems));
	faifa_printf (out_stream, "Extended Smaller GI Support Flag: %s\n", sound->esgisf ? "Yes" : "No");
	faifa_printf (out_stream, "Extended Larger GI Support Flag: %s\n", sound->elgisf ? "Yes" : "No");
	faifa_printf (out_stream, "Extended FEC Rate Support: %u (0x0%02hx)\n", (short unsigned int)(sound->efrs),(short unsigned int)(sound->efrs));
	faifa_printf (out_stream, "Frame control check sequence: 0x0%2hx%2hx%2hx\n",
		(unsigned int)(sound->fccs_av[0]),
		(unsigned int)(sound->fccs_av[1]),
		(unsigned int)(sound->fccs_av[2]));
}

/*
6. Function for decoding delimiter = reverse start of frame - IEEE 1910-2010 Table 6-46
*/

void dump_hpav_rsof(struct hpav_rsof *rsof)
{
	faifa_printf (out_stream, "DTEI: %u (0x0%02hx)\n", (short unsigned int)(rsof->dtei),(short unsigned int)(rsof->dtei));
	faifa_printf (out_stream, "Contention free session: %s\n", rsof->cfs ? "Yes" : "No (CSMA)");
	faifa_printf (out_stream, "Beacon detected: %s\n", rsof->bdf ? "Yes" : "No");
	faifa_printf (out_stream, "Sack version number: %s\n",rsof->svn ? "1" : "0");
	faifa_printf (out_stream, "Request Reverse Transmission: %s\n", rsof->rrtf ? "Yes" : "No");
	faifa_printf (out_stream, "Data MAC Frame Stream Response: %u (0x0%1hx)\n", (short unsigned int)(rsof->mfs_rsp_data),(short unsigned int)(rsof->mfs_rsp_data));
	faifa_printf (out_stream, "Management MAC Frame Stream Response: %u (0x0%1hx)\n", (short unsigned int)(rsof->mfs_rsp_mgmt),(short unsigned int)(rsof->mfs_rsp_mgmt));
	faifa_printf (out_stream, "Reverse SOF Frame length: %u (0x0%3hx) = ", rsof->rsof_fl,rsof->rsof_fl);
	if ((rsof->rsof_fl < 0x3e) || (rsof->rsof_fl > 0x3ff)) 
		{
		faifa_printf (out_stream, "Reserved\n");
		}
	else
		{
		if (rsof->rsof_fl < 0x200) 
			{
			faifa_printf (out_stream, "%g usec\n", ((float)(rsof->rsof_fl*128/100)));
			}
		else
			{
			faifa_printf (out_stream, "%g usec\n", ((float)(rsof->rsof_fl*256/100)));
			}
		}
	faifa_printf (out_stream, "1901 Tone Map Index: %u (0x0%02hx)\n", (short unsigned int)(rsof->tmi),(short unsigned int)(rsof->tmi));
	faifa_printf (out_stream, "PHY block size: %s\n", rsof->pbsz ? "Yes" : "No");
	faifa_printf (out_stream, "Number of Symbols: %u (0x0%1hx)\n", (short unsigned int)(rsof->numsym),(short unsigned int)(rsof->numsym));
	faifa_printf (out_stream, "Management MAC Frame Stream Command: %u (0x0%1hx)\n", (short unsigned int)(rsof->mfscmdmg),(short unsigned int)(rsof->mfscmdmg));
	faifa_printf (out_stream, "Data MAC Frame Stream Command: %u (0x0%1hx)\n", (short unsigned int)(rsof->mfscmdd),(short unsigned int)(rsof->mfscmdd));
	faifa_printf (out_stream, "Frame control check sequence: 0x0%2hx%2hx%2hx\n",
		(unsigned int)(rsof->fccs_av[0]),
		(unsigned int)(rsof->fccs_av[1]),
		(unsigned int)(rsof->fccs_av[2]));
}

/***************************************************************************/

/*
7. Function for dumping beacon mpdu payload according to IEEE 1901-2010 Table 6-63
*/

void dump_beacon_mpdu_payload (struct beacon_mpdu_payload *bmp)
{
	faifa_printf (out_stream, "\nBeacon MPDU payload:\n");
	faifa_printf (out_stream,  "Network Identifier: %02hx:%02hx:%02hx:%02hx:%02hx:%02hx:%02hx\n",bmp->nid0,bmp->nid1,bmp->nid2,bmp->nid3,bmp->nid4,bmp->nid5,bmp->nid6);
	faifa_printf (out_stream,  "1901 FTT Hybrid Mode: %u (0x0%02hx) = ",bmp->hm,bmp->hm);
	switch (bmp->hm)
		{
		case 0:
		faifa_printf (out_stream, "FFT-only mode\n");
		break;
		case 1:
		faifa_printf (out_stream, "Only in shared CSMA allocations\n");
		break;
		case 2:
		faifa_printf (out_stream, "Fully hybrid in all CSMA, CFPI, and CFP allocations\n");
		break;
		case 3:
		faifa_printf (out_stream, "Hybrid delimiters, non-TIA 1113 frame lengths, CSMA-only mode\n");
		default:
		break;
		}
	faifa_printf (out_stream,  "STEI: %u (0x0%02hx)\n",(short unsigned int)(bmp->stei),(short unsigned int)(bmp->stei));
	faifa_printf (out_stream,  "Beacon Type: %u (0x0%02hx) = ",bmp->bt,bmp->bt);
	switch (bmp->bt)
		{
		case 0:
		faifa_printf (out_stream, "Central");
		break;
		case 1:
		faifa_printf (out_stream, "Discover");
		break;
		case 2:
		faifa_printf (out_stream, "Proxy");
		break;
		case 3:
		faifa_printf (out_stream, "Reserved");
		default:
		break;
		}
	faifa_printf (out_stream, "\n");
	faifa_printf (out_stream,  "Uncoordinated Networks Reported: %s\n",bmp->ucnr ? "Yes" : "No");
	faifa_printf (out_stream,  "Network Power-Saving Mode: %s\n",bmp->npsm ? "Yes" : "No");
	faifa_printf (out_stream,  "Number of Beacon Slots: %u (0x0%02hx) = %u\n",(short unsigned int)(bmp->numslots),(short unsigned int)(bmp->numslots),(short unsigned int)(bmp->numslots+1));	// 8
	faifa_printf (out_stream,  "Beacon Slot Usage (bitmapped): %u (0x0%02hx) = ",(short unsigned int)(bmp->slotusage),(short unsigned int)(bmp->slotusage));		// 9
	int bit ;
	for (bit = 128 ; bit > 0 ; bit >>= 1)
		faifa_printf (out_stream,"%s", (bmp->slotusage & bit) ? "1" : "0");
	faifa_printf (out_stream,  "\n");
	faifa_printf (out_stream,  "Beacon Slot ID: %u (0x0%02hx) = %u\n",(short unsigned int)(bmp->slotid),(short unsigned int)(bmp->slotid),(short unsigned int)(bmp->slotid+1));
	faifa_printf (out_stream,  "AC Line Cycle Synchronization Status: %u (0x0%02hx)\n",(short unsigned int)(bmp->aclss),(short unsigned int)(bmp->aclss));
	faifa_printf (out_stream,  "Handover-In-Progress: %u (0x0%02hx)\n",(short unsigned int)(bmp->hoip),(short unsigned int)(bmp->hoip));
	faifa_printf (out_stream,  "RTS Broadcast: %s\n",bmp->rtsbf ? "Yes" : "No");		// 10
	faifa_printf (out_stream,  "Network Mode: %u (0x0%02hx) = ",bmp->nm,bmp->nm);
	switch (bmp->nm)
		{
		case 0:
		faifa_printf (out_stream, "Uncoordinated mode");
		break;
		case 1:
		faifa_printf (out_stream, "Coordinated mode");
		break;
		case 2:
		faifa_printf (out_stream, "CSMA-Only mode");
		break;
		case 3:
		faifa_printf (out_stream, "Reserved");
		default:
		break;
		}
	faifa_printf (out_stream, "\n");
	faifa_printf (out_stream,  "BSS Manager Capability: %u (0x0%02hx) = Level ",bmp->bmcap,bmp->bmcap);
	switch (bmp->bmcap)
		{
		case 0:
		faifa_printf (out_stream, "0 - CSMA-only mode no QoS/TDMA support");
		break;
		case 1:
		faifa_printf (out_stream, "1 - Uncoordinated mode QoS/TDMA support");
		break;
		case 2:
		faifa_printf (out_stream, "2 - Coordinated mode QoS/TDMA support");
		break;
		case 3:
		faifa_printf (out_stream, "3 - Reserved");
		default:
		break;
		}
	faifa_printf (out_stream, "\n");
	faifa_printf (out_stream,  "Reusable SNID: %s\n",bmp->rsf ? "Yes" : "No");
	faifa_printf (out_stream,  "Proxy Level: %u (0x0%02hx)\n",(short unsigned int)(bmp->plevel),(short unsigned int)(bmp->plevel));		// 11
	faifa_printf (out_stream,  "Beacon Payload Check Sequence: %04x\n",(u_int32_t)(bmp->bpcs));		// 132-135
}

/* The following function includes amendments (c) Andrew Margolis to make faifa conform better to 
   IEEE 1901-2010 standards by decoding all six possible delimiters in sniffed frames properly.*/

static int hpav_dump_sniffer_indicate(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	struct sniffer_indicate *mm = buf;
	faifa_printf(out_stream, "Type: %s\n", mm->type ? "Unknown" : "Regular");
	faifa_printf(out_stream, "Direction: %s\n", mm->direction ? "Rx" : "Tx");
	faifa_printf(out_stream, "System time: %"SCNu64" (0x0%08x)\n", mm->systime, (unsigned int)mm->systime);
	faifa_printf(out_stream, "Beacon time: %u (0x0%04x)\n\n", mm->beacontime,mm->beacontime);
	faifa_printf(out_stream, "Delimiter type: %u (0x0%1hhx = ", mm->del_type,mm->del_type);
	switch (mm->del_type)
	{
	case 0: // binary 000
		faifa_printf(out_stream, "Beacon");
		break;
	case 1: // binary 001
		faifa_printf(out_stream, "Start of Frame");
		break;
	case 2: //binary 010
		faifa_printf(out_stream, "Selective Acknowledgement");
		break;
	case 3: //binary 011
		faifa_printf(out_stream, "RTS/CTS");
		break;
	case 4: // binary 100
		faifa_printf(out_stream, "Sound");
		break;
	case 5: // binary 101
		faifa_printf(out_stream, "Reverse Start of Frame");
		break;
	default:
		faifa_printf(out_stream, "Reserved");
		break;
	}
	printf (")\n");
	faifa_printf (out_stream, "Access field: %u (0x0%1hhx) = ", mm->access, mm->access);
	faifa_printf (out_stream, "%s\n", mm->access ? "Access Network" : "In-home Network");
	faifa_printf(out_stream, "SNID: %u (0x0%1hhx)\n", mm->snid, mm->snid);
	
	switch (mm->del_type) {
	case 0: // binary 000
		faifa_printf(out_stream, "Beacon variant fields:\n");
		dump_hpav_beacon(&(mm->bcn));
		if ((len - sizeof (*mm)) >= 136) // check we have the data for the 136 octet beacon payload
			{ 
			struct beacon_mpdu_payload *bmp = buf+sizeof(*mm) ;
			dump_beacon_mpdu_payload (bmp);
			avail -= sizeof(*bmp);
			}
		break;
	case 1: // binary 001
		faifa_printf(out_stream, "Start of Frame variant fields:\n");
		dump_hpav_frame_ctl(&(mm->fc));
		break;
	case 2: //binary 010
		faifa_printf(out_stream, "Selective Acknowledgement variant fields:\n");
		dump_hpav_sack(&(mm->sack));
		break;
	case 3: //binary 011
		faifa_printf(out_stream, "RTS/CTS variant fields:\n");
		dump_hpav_rtscts(&(mm->rtscts));
		break;
	case 4: // binary 100
		faifa_printf(out_stream, "Sound variant fields:\n");
		dump_hpav_sound(&(mm->sound));
		break;
	case 5: // binary 101
		faifa_printf(out_stream, "Reverse Start of Frame variant fields:\n");
		dump_hpav_rsof(&(mm->rsof));
		break;
	default:
		faifa_printf(out_stream, "Undecoded (reserved delimiter)\n");
		break;
	}

	avail -= sizeof(*mm);

	return (len - avail);
}

static int hpav_init_check_points_request(void *buf, int len, void *UNUSED(buffer))
{
	int avail = len;
	struct check_points_request *mm = buf;

	srand(getpid());
	mm->session_id = (unsigned int)(random());
	/* Do not clear the check points yet */
	mm->clr_flag = 0x00;

	avail -= sizeof(*mm);

	return (len - avail);
}

char *get_sta_role_str(u_int8_t sta_role)
{
	switch (sta_role) {
	case HPAV_SR_STA:
		return "Station";
	case HPAV_SR_PROXY:
		return "Proxy coordinator";
	case HPAV_SR_CCO:
		return "Network coordinator";
	default:
		return NULL;
	}

	return NULL;
}

static int hpav_dump_network_info_confirm(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	struct network_info_confirm *mm = buf;
	int i;

	faifa_printf(out_stream, "Network ID (NID): "); dump_hex(&(mm->nid), sizeof(mm->nid), " ");
	faifa_printf(out_stream, "\n");
	faifa_printf(out_stream, "Short Network ID (SNID): 0x%02hx\n", mm->snid);
	faifa_printf(out_stream, "STA TEI: 0x%02hx\n", mm->tei);
	faifa_printf(out_stream, "STA Role: %s\n", get_sta_role_str(mm->sta_role));
	faifa_printf(out_stream, "CCo MAC: \n");
	faifa_printf(out_stream, "\t"); dump_hex(&(mm->cco_macaddr), sizeof(mm->cco_macaddr), ":");
	faifa_printf(out_stream, "\nCCo TEI: 0x%02hx\n", mm->cco_tei);
	faifa_printf(out_stream, "Stations: %d\n", mm->num_stas);
	avail -= sizeof(*mm);
	if (mm->num_stas > 0) {
		faifa_printf(out_stream, "Station MAC       TEI  Bridge MAC        TX   RX  \n");
		faifa_printf(out_stream, "----------------- ---- ----------------- ---- ----\n");
		for (i = 0; i < mm->num_stas; i++) {
			dump_hex(mm->stas[i].sta_macaddr, sizeof(mm->stas[i].sta_macaddr), ":");
			faifa_printf(out_stream, " 0x%02hx ", mm->stas[i].sta_tei);
			dump_hex(mm->stas[i].bridge_macaddr, sizeof(mm->stas[i].bridge_macaddr), ":");
			faifa_printf(out_stream, " 0x%02hx", mm->stas[i].avg_phy_tx_rate);
			faifa_printf(out_stream, " 0x%02hx\n", mm->stas[i].avg_phy_rx_rate);
		}
	}

	return (len - avail);
}


static int hpav_dump_check_points_indicate(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	struct check_points_indicate *mm = buf;

	faifa_printf(out_stream, "Status: %s\n", mm->mstatus ? "Failure" : "Success");
	faifa_printf(out_stream, "Major: %s\n", mm->major ? "< 1.4" : "> 1.4");
	faifa_printf(out_stream, "Checkpoint buffer locked: %s\n", mm->buf_locked ? "Yes" : "No");
	faifa_printf(out_stream, "Auto-lock on reset supported: %s\n", mm->auto_lock ? "Yes" : "No");
	faifa_printf(out_stream, "Unsollicited update supported: %s\n", mm->unsoc_upd ? "Yes" : "No");
	faifa_printf(out_stream, "Unsollicited: %s\n", mm->unsoc ? "Yes" : "No");
	faifa_printf(out_stream, "Session: %04hx\n", mm->session_id);
	faifa_printf(out_stream, "Length: %u (0x%08x)\n", mm->length, mm->length);
	faifa_printf(out_stream, "Offset: 0x%08x\n", mm->offset);
	faifa_printf(out_stream, "Next index: 0x%08x\n", mm->index);
	faifa_printf(out_stream, "Number of parts: %d\n", mm->num_parts);
	faifa_printf(out_stream, "Current part: %d\n", mm->cur_part);
	faifa_printf(out_stream, "Data length: %d (0x%04hx)\n", mm->data_length, mm->data_length);
	faifa_printf(out_stream, "Data offset: 0x%04hx\n", mm->data_offset);
	/* FIXME: we should probably move the offset */
	//dump_hex(mm->data + mm->data_offset, (unsigned int)(mm->data_length), " ");
	avail -= sizeof(*mm);

	return (len - avail);
}

static int hpav_dump_loopback_request(void *buf, int len, void *UNUSED(buffer))
{
	int avail = len;
	struct loopback_request *mm = buf;
	int duration;
	u_int8_t eth_test_frame[512];

	faifa_printf(out_stream, "Duration ?\n");
	fscanf(in_stream, "%2d", &duration);
	if (duration >= 0 || duration <= 60)
		mm->duration = duration;

	/* FIXME: building a static test frame */
	ether_init_header(eth_test_frame, 512, broadcast_macaddr, broadcast_macaddr, ETHERTYPE_HOMEPLUG_AV);
	memcpy(mm->data, eth_test_frame, sizeof(eth_test_frame));

	avail -= sizeof(*mm);

	return (len - avail);
}


static int hpav_dump_loopback_confirm(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	struct loopback_confirm *mm = buf;

	faifa_printf(out_stream, "Status: %s\n", mm->mstatus ? "Failure" : "Success");
	faifa_printf(out_stream, "Duration: %d\n", mm->duration);
	faifa_printf(out_stream, "Length: %d\n", mm->length);
	avail -= sizeof(*mm);

	return (len - avail);
}

static int hpav_dump_loopback_status_confirm(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	struct loopback_status_confirm *mm = buf;

	faifa_printf(out_stream, "Status: %s\n", mm->mstatus ? "Failure" : "Success");
	faifa_printf(out_stream, "State: %s\n", mm->state ? "Looping frame" : "Done");
	avail -= sizeof(*mm);

	return (len - avail);
}

static int hpav_init_set_enc_key_request(void *buf, int len, void *UNUSED(user))
{
	int avail = len;
	struct set_encryption_key_request *mm = buf;
	int local;
	u_int8_t key[16], dak[16];
	char nek[16], dek[16];
	u_int8_t macaddr[ETHER_ADDR_LEN];

	faifa_printf(out_stream, "Local or distant setting ?\n");
	faifa_printf(out_stream, "0: distant\n1: local\n");
	fscanf(in_stream, "%d", &local);

	/* Old versions should use 0x03 */
	mm->peks = 0x01;
	mm->peks_payload = NO_KEY;
	faifa_printf(out_stream, "AES NMK key ?");
	fscanf(in_stream, "%s", nek);

	/* Generate the key from the NEK and and NMK Salt */
	gen_passphrase(nek, key, nmk_salt);
	memcpy(mm->nmk, key, AES_KEY_SIZE);

	/* If we are setting a remote device ask for more options */
	if (!local) {
		faifa_printf(out_stream, "Device DEK ?\n");
		fscanf(in_stream, "%s", dek);

		/* Generate the key from the DEK and DAK salt */
		gen_passphrase(dek, dak, dak_salt);
		memcpy(mm->dak, dak, AES_KEY_SIZE);
		mm->peks_payload = DST_STA_DAK;

		/* Broadcast the key */
		memset(mm->rdra, 0xFF, ETHER_ADDR_LEN);
	} else {
		/* Ask for the station MAC address */
		faifa_printf(out_stream, "Destination MAC address ?");
		fscanf(in_stream, "%02hhx:%02hhx:%02hhx:%2hhx:%2hhx:%2hhx",
			&macaddr[0], &macaddr[1], &macaddr[2],
			&macaddr[3], &macaddr[4], &macaddr[5]);

		/* Set the desination address */
		memcpy(mm->rdra, macaddr, ETHER_ADDR_LEN);
	}

	avail -= sizeof(*mm);

	return (len - avail);
}

static int hpav_dump_set_enc_key_confirm(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	short unsigned int *status = (short unsigned int *)buf;

	switch(*status) {
	case KEY_SUCCESS:
		faifa_printf(out_stream, "Status: Success\n");
		break;
	case KEY_INV_EKS:
		faifa_printf(out_stream, "Status: Invalid EKS\n");
		break;
	case KEY_INV_PKS:
		faifa_printf(out_stream, "Status: Invalid PKS\n");
		break;
	case KEY_UKN:
		faifa_printf(out_stream, "Unknown result: %02hx\n", *status);
		break;
	}
	avail -= sizeof(*status);

	return (len - avail);
}

static const char *get_peks_str(u_int8_t peks)
{
	switch (peks) {
	case DST_STA_DAK:
		return "Destination Station DAK";
	case NMK_KNOWN_STA:
		return "NMK known to station";
	case ID_TEKS:
	case 0x03:
	case 0x04:
	case 0x05:
	case 0x06:
	case 0x07:
	case 0x08:
	case 0x09:
	case 0x0A:
	case 0x0B:
	case 0x0C:
	case 0x0D:
	case 0x0E:
		return "Identifies TEKs";
	case NO_KEY:
	default:
		return "No key";
	}

	return NULL;
}

static const char *get_avln_status_str(u_int8_t avln_status)
{
	switch (avln_status) {
	case UN_ASSOC_LVL_0:
		return "Unassociated and Level-0 CCo capable";
	case UN_ASSOC_LVL_1:
		return "Unassociated and Level-1 CCo capable";
	case UN_ASSOC_LVL_2:
		return "Unassociated and Level-2 CCo capable";
	case UN_ASSOC_LVL_3:
		return "Unassociated and Level-3 CCo capable";
	case UN_ASSOC_NPCO:
		return "Associated with AV LAN but not PCo capable";
	case UN_ASSOC_PCO:
		return "Associated with AV LAN and PCo capable";
	case CCO_AVLN:
		return "CCo of an AV LAN";
	default:
		return NULL;
	}

	return NULL;
}

static const char *get_pid_str(u_int8_t pid)
{
	switch (pid) {
	case AUTH_REQ_NEW:
		return "Authentication request by new STA";
	case PROV_STA_NEW:
		return "Provision authenticated STA with new NEK by CCo";
	case PROV_STA_DAK:
		return "Provision STA with NMK using DAK";
	case PROV_STA_UKE:
		return "Provision STA with NMK using UKE";
	case HLE_PROTO:
		return "HLE protocol";
	default:
		return NULL;
	}

	return NULL;
}

static int hpav_dump_enc_payload_indicate(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	struct cm_enc_payload_indicate *mm = buf;
	unsigned proto = 0;

	if (mm->pid == HLE_PROTO)
		proto = 1;

	faifa_printf(out_stream, "PEKS: %s\n", get_peks_str(mm->peks));
	faifa_printf(out_stream, "HPAV Lan status: %s\n", get_avln_status_str(mm->avln_status));
	faifa_printf(out_stream, "PID: %s\n", get_pid_str(mm->pid));
	faifa_printf(out_stream, "PRN: %02hhx\n", mm->prn);
	faifa_printf(out_stream, "PMN: %02hhx\n", mm->pmn);
	faifa_printf(out_stream, "%s: ", proto ? "UUID" : "AES IV");
	dump_hex(mm->aes_iv_uuid, AES_KEY_SIZE, " ");
	faifa_printf(out_stream, "\n");

	avail -= sizeof(*mm);

	return (len - avail);
}

static int hpav_dump_enc_payload_response(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	struct cm_enc_payload_response *mm = buf;

	faifa_printf(out_stream, "Result: %s\n", mm->result ? "Failure/Abort" : "Success");
	faifa_printf(out_stream, "PID: %s\n", get_pid_str(mm->pid));
	faifa_printf(out_stream, "PRN: %02hx\n", mm->prn);
	avail -= sizeof(*mm);

	return (len - avail);
}

static const char *get_key_type_str(u_int8_t key_type)
{
	switch (key_type) {
	case DAK_AES_128:
		return "DAK (AES-128)";
	case NMK_AES_128:
		return "NMK (AES-128)";
	case NEK_AES_128:
		return "NEK (AES-128)";
	case TEK_AES_128:
		return "TEK (AES-128)";
	case HASH_KEY:
		return "Hash key";
	case NONCE_ONLY:
		return "Nonce only";
	default:
		return NULL;
	}

	return NULL;
}

static int hpav_dump_cm_set_key_request(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	struct cm_set_key_request *mm = buf;

	faifa_printf(out_stream, "Key type: %s\n", get_key_type_str(mm->key_type));
	faifa_printf(out_stream, "My nonce: %08x\n", mm->my_nonce);
	faifa_printf(out_stream, "Your nonce: %08x\n", mm->your_nonce);
	faifa_printf(out_stream, "PID: %s\n", get_pid_str(mm->pid));
	faifa_printf(out_stream, "PRN: %02hhx\n", mm->prn);
	faifa_printf(out_stream, "CCo cap: %02hhx\n", mm->cco_cap);
	faifa_printf(out_stream, "NID ");
	dump_hex(mm->nid, sizeof(mm->nid), "");
	faifa_printf(out_stream, "\n");
	faifa_printf(out_stream, "New EKS: %02hhx\n", mm->new_eks);
	faifa_printf(out_stream, "New Key: ");
	dump_hex(mm->new_key, AES_KEY_SIZE, "");
	faifa_printf(out_stream, "\n");

	avail -= sizeof(*mm);

	return (len - avail);
}

static int hpav_dump_cm_set_key_confirm(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	struct cm_set_key_confirm *mm = buf;

	faifa_printf(out_stream, "Result: %s\n", mm->result ? "Failure" : "Success");
	faifa_printf(out_stream, "My nonce: %08lx\n", (long unsigned int)(mm->my_nonce));
	faifa_printf(out_stream, "Your nonce: %08lx\n", (long unsigned int)(mm->your_nonce));
	faifa_printf(out_stream, "PID: %s\n", get_pid_str(mm->pid));
	faifa_printf(out_stream, "PRN: %02hx\n", (short unsigned int)(mm->prn));
	faifa_printf(out_stream, "CCo cap: %02hx\n", (short unsigned int)(mm->cco_cap));

	avail -= sizeof(*mm);

	return (len - avail);
}

static int hpav_dump_cm_get_key_request(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	struct cm_get_key_request *mm = buf;

	faifa_printf(out_stream, "Request type: %s\n", mm->req_type ? "Relayed" : "Direct");
	faifa_printf(out_stream, "Key type: %s\n", get_key_type_str(mm->req_key_type));
	faifa_printf(out_stream, "NID "); dump_hex(mm->nid, sizeof(mm->nid), "");faifa_printf(out_stream, "\n");
	faifa_printf(out_stream, "My nonce: %08x\n", mm->my_nonce);
	faifa_printf(out_stream, "PID: %s\n", get_pid_str(mm->pid));
	faifa_printf(out_stream, "PRN: %02hhx\n", mm->prn);
	faifa_printf(out_stream, "PMN: %02hhx\n", mm->pmn);
	if (mm->req_key_type == HASH_KEY)
		faifa_printf(out_stream, "Hash key: ");dump_hex(mm->hash_key, len, "");faifa_printf(out_stream, "\n");

	avail -= sizeof(*mm);

	return (len - avail);
}

static const char *get_key_result_str(u_int8_t result)
{
	switch (result) {
	case 0x00:
		return "Key granted";
	case 0x01:
		return "Key refused";
	case 0x02:
		return "Unsupported key/method";
	default:
		return NULL;
	}

	return NULL;
}

static int hpav_dump_cm_get_key_confirm(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	struct cm_get_key_confirm *mm = buf;

	faifa_printf(out_stream, "Result :%s\n", get_key_result_str(mm->result));
	faifa_printf(out_stream, "Key type: %s\n", get_key_type_str(mm->req_key_type));
	faifa_printf(out_stream, "My nonce: %08x\n", mm->my_nonce);
	faifa_printf(out_stream, "Your nonce: %08x\n", mm->your_nonce);
	faifa_printf(out_stream, "NID "); dump_hex(mm->nid, sizeof(mm->nid), "");faifa_printf(out_stream, "\n");
	faifa_printf(out_stream, "EKS: %02hhx\n", mm->eks);
	faifa_printf(out_stream, "PID: %s\n", get_pid_str(mm->pid));
	faifa_printf(out_stream, "PRN: %02hhx\n", mm->prn);
	faifa_printf(out_stream, "PMN: %02hhx\n", mm->pmn);
	faifa_printf(out_stream, "Hash key: ");dump_hex(mm->key, len, "");faifa_printf(out_stream, "\n");

	avail -= sizeof(*mm);

	return (len - avail);
}

static int hpav_dump_cm_bridge_infos_confirm(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	struct cm_brigde_infos_confirm *mm = buf;

	faifa_printf(out_stream, "Bridging: %s\n", mm->bsf ? "Yes" : "No");
	if (mm->bsf) {
		int i;

		faifa_printf(out_stream, "Bridge TEI: %02hhx\n", mm->bridge_infos.btei);
		faifa_printf(out_stream, "Number of stations: %d\n", mm->bridge_infos.nbda);
		for (i = 0; i < mm->bridge_infos.nbda; i++) {
			faifa_printf(out_stream, "Bridged station %d", i);
			dump_hex(mm->bridge_infos.bri_addr[i], ETHER_ADDR_LEN, ":");
			faifa_printf(out_stream, "\n");
		}
	}

	avail -= sizeof(*mm);

	return (len - avail);
}

static const char *get_net_access_str(u_int8_t access)
{
	switch (access) {
	case 0x00:
		return "In-Home network";
	case 0x01:
		return "Access network";
	default:
		return "Unknown";

	}
	return NULL;
}

static void dump_cm_net_info(struct cm_net_info *net_info)
{
	faifa_printf(out_stream, "NID: ");
	dump_hex(net_info->nid, sizeof(net_info->nid), " ");
	faifa_printf(out_stream, "\n");
	faifa_printf(out_stream, "TEI: 0x%02hX (%d)\n", net_info->tei, net_info->tei);
	faifa_printf(out_stream, "STA Role: 0x%02hX (%s)\n",
		net_info->sta_role, get_sta_role_str(net_info->sta_role));
	faifa_printf(out_stream, "MAC address: ");
	dump_hex(net_info->macaddr, ETHER_ADDR_LEN, ":");
	faifa_printf(out_stream, "\n");
	faifa_printf(out_stream, "Access: 0x%02hX (%s)\n",
		net_info->access, get_net_access_str(net_info->access));
	faifa_printf(out_stream, "Number of neighbors: %d\n", net_info->num_cord);
}

static int hpav_dump_cm_get_network_infos_confirm(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	struct cm_get_network_infos_confirm *mm = buf;
	int i;

	avail -= sizeof(*mm);
	for (i = 0; i < mm->net.count; i++) {
		dump_cm_net_info(&(mm->net.infos[i]));
		avail -= sizeof(mm->net.infos[i]);
	}

	return (len - avail);
}

static void dump_cm_sta_info(struct cm_sta_info *sta_info)
{
	faifa_printf(out_stream, "MAC address: ");
	dump_hex(sta_info->macaddr, ETHER_ADDR_LEN, ":");
	faifa_printf(out_stream, "\n");
	faifa_printf(out_stream, "Average data rate from STA to DA: %d\n", sta_info->avg_phy_dr_tx);
	faifa_printf(out_stream, "Average data rate from DA to STA: %d\n", sta_info->avg_phy_dr_rx);
}

static int hpav_dump_cm_get_network_stats_confirm(void *buf, int len, struct ether_header *UNUSED(hdr))
{
	int avail = len;
	struct cm_get_network_stats_confirm *mm = buf;
	int i;

	avail -= sizeof(*mm);
	for (i = 0; i < mm->sta.count; i++) {
		dump_cm_sta_info(&(mm->sta.infos[i]));
		avail -= sizeof(mm->sta.infos[i]);
	}

	return (len - avail);
}

/**
 * frame_ops - array of the available frame operations
 */
struct hpav_frame_ops hpav_frame_ops[] = {
	{
		.mmtype = HPAV_MMTYPE_CC_DISC_LIST_REQ,
		.desc = "Central Coordination Discover List Request",
		.init_frame = init_empty_frame,
	}, {
		.mmtype = HPAV_MMTYPE_CC_DISC_LIST_CNF,
		.desc = "Central Coordination Discover List Confirm",
		.dump_frame = hpav_dump_cc_discover_list_confirm,
	}, {
		.mmtype = HPAV_MMTYPE_CM_ENC_PLD_IND,
		.desc = "Encrypted Payload Indicate",
		.dump_frame = hpav_dump_enc_payload_indicate,
	}, {
		.mmtype = HPAV_MMTYPE_CM_ENC_PLD_RSP,
		.desc = "Encrypted Payload Response",
		.dump_frame = hpav_dump_enc_payload_response,
	}, {
		.mmtype = HPAV_MMTYPE_CM_SET_KEY_REQ,
		.desc = "Set Key Request",
		.dump_frame = hpav_dump_cm_set_key_request,
	}, {
		.mmtype = HPAV_MMTYPE_CM_SET_KEY_CNF,
		.desc = "Set Key Confirm",
		.dump_frame = hpav_dump_cm_set_key_confirm,
	}, {
		.mmtype = HPAV_MMTYPE_CM_GET_KEY_REQ,
		.desc = "Get Key Request",
		.dump_frame = hpav_dump_cm_get_key_request,
	}, {
		.mmtype = HPAV_MMTYPE_CM_GET_KEY_CNF,
		.desc = "Get Key Confirm",
		.dump_frame = hpav_dump_cm_get_key_confirm,
	}, {
		.mmtype = HPAV_MMTYPE_CM_BRG_INFO_REQ,
		.desc = "Get Bridge Infos Request",
		.init_frame = init_empty_frame,
	}, {
		.mmtype = HPAV_MMTYPE_CM_BRG_INFO_CNF,
		.desc = "Get Bridge Infos Confirm",
		.dump_frame = hpav_dump_cm_bridge_infos_confirm,
	}, {
		.mmtype = HPAV_MMTYPE_CM_NW_INFO_REQ,
		.desc = "Get Network Infos Request",
		.init_frame = init_empty_frame,
	}, {
		.mmtype = HPAV_MMTYPE_CM_NW_INFO_CNF,
		.desc = "Get Network Infos Confirm",
		.dump_frame = hpav_dump_cm_get_network_infos_confirm,
	}, {
		.mmtype = HPAV_MMTYPE_CM_NW_STATS_REQ,
		.desc = "Get Network Stats Request",
		.init_frame = init_empty_frame,
	}, {
		.mmtype = HPAV_MMTYPE_CM_NW_STATS_CNF,
		.desc = "Get Network Stats Confirm",
		.dump_frame = hpav_dump_cm_get_network_stats_confirm,
	}, {
		.mmtype = HPAV_MMTYPE_GET_SW_REQ,
		.desc = "Get Device/SW Version Request",
		.init_frame = init_empty_frame,
	}, {
		.mmtype = HPAV_MMTYPE_GET_SW_CNF,
		.desc = "Get Device/SW Version Confirm",
		.dump_frame = hpav_dump_get_device_sw_version_confirm,
	}, {
		.mmtype = HPAV_MMTYPE_WR_MEM_REQ,
		.desc = "Write MAC Memory Request",
		.init_frame = hpav_init_write_mac_memory_request,
		.dump_frame = hpav_dump_write_mac_memory_request,
	}, {
		.mmtype = HPAV_MMTYPE_WR_MEM_CNF,
		.desc = "Write MAC Memory Confirm",
		.dump_frame = hpav_dump_write_mac_memory_confirm,
	}, {
		.mmtype = HPAV_MMTYPE_RD_MEM_REQ,
		.desc = "Read MAC Memory Request",
		.init_frame = hpav_init_read_mac_memory_request,
		.dump_frame = hpav_dump_read_mac_memory_request,
	}, {
		.mmtype = HPAV_MMTYPE_RD_MEM_CNF,
		.desc = "Read MAC Memory Confirm",
		.dump_frame = hpav_dump_read_mac_memory_confirm,
	}, {
		.mmtype = HPAV_MMTYPE_ST_MAC_REQ,
		.desc = "Start MAC Request",
		.init_frame = hpav_init_start_mac_request,
		.dump_frame = hpav_dump_start_mac_request,
	}, {
		.mmtype = HPAV_MMTYPE_ST_MAC_CNF,
		.desc = "Start MAC Confirm",
		.dump_frame = hpav_dump_start_mac_confirm,
	}, {
		.mmtype = HPAV_MMTYPE_GET_NVM_REQ,
		.desc = "Get NVM parameters Request",
	}, {
		.mmtype = HPAV_MMTYPE_GET_NVM_CNF,
		.desc = "Get NVM parameters Confirm",
		.dump_frame = hpav_dump_nvram_params_confirm,
	}, {
		.mmtype = HPAV_MMTYPE_RS_DEV_REQ,
		.desc = "Reset Device Request",
		.init_frame = init_empty_frame,
	}, {
		.mmtype = HPAV_MMTYPE_RS_DEV_CNF,
		.desc = "Reset Device Confirm",
		.dump_frame = hpav_dump_reset_device_confirm,
	}, {
		.mmtype = HPAV_MMTYPE_WR_MOD_REQ,
		.desc = "Write Module Data Request",
		.init_frame = hpav_init_write_data_request,
	}, {
		.mmtype = HPAV_MMTYPE_WR_MOD_CNF,
		.desc = "Write Module Data Confirm",
		.dump_frame = hpav_dump_write_mod_data_confirm,
	}, {
		.mmtype = HPAV_MMTYPE_WR_MOD_IND,
		.desc = "Write Module Data Indicate",
	}, {
		.mmtype = HPAV_MMTYPE_RD_MOD_REQ,
		.desc = "Read Module Data Request",
		.init_frame = hpav_init_read_mod_data_request,
	}, {
		.mmtype = HPAV_MMTYPE_RD_MOD_CNF,
		.desc = "Read Module Data Confirm",
		.dump_frame = hpav_dump_read_mod_data_confirm,
	}, {
		.mmtype = HPAV_MMTYPE_NVM_MOD_REQ,
		.desc = "Write Module Data to NVM Request",
	}, {
		.mmtype = HPAV_MMTYPE_NVM_MOD_CNF,
		.desc = "Write Module Data to NVM Confirm",
		.dump_frame = hpav_dump_start_mac_confirm,
	}, {
		.mmtype = HPAV_MMTYPE_WD_RPT_REQ,
		.desc = "Get Watchdog Report Request",
		.init_frame = hpav_init_watchdog_report_request,
	}, {
		.mmtype = HPAV_MMTYPE_WD_RPT_IND,
		.desc = "Get Watchdog Report Indicate",
		.dump_frame = hpav_dump_watchdog_report_indicate,
	}, {
		.mmtype = HPAV_MMTYPE_LNK_STATS_REQ,
		.desc = "Get Link Statistics Request",
		.init_frame = hpav_init_link_stats_request,
	}, {
		.mmtype = HPAV_MMTYPE_LNK_STATS_CNF,
		.desc = "Get Link Statistics Confirm",
		.dump_frame = hpav_dump_link_stats_confirm,
	}, {
		.mmtype = HPAV_MMTYPE_SNIFFER_REQ,
		.desc = "Sniffer Mode Request",
		.init_frame = hpav_init_sniffer_request,
		.dump_frame = hpav_dump_sniffer_request,
	}, {
		.mmtype = HPAV_MMTYPE_SNIFFER_CNF,
		.desc = "Sniffer Mode Confirm",
		.dump_frame = hpav_dump_sniffer_confirm,
	}, {
		.mmtype = HPAV_MMTYPE_SNIFFER_IND,
		.desc = "Sniffer Mode Indicate",
		.dump_frame = hpav_dump_sniffer_indicate,
	}, {
		.mmtype = HPAV_MMTYPE_NW_INFO_REQ,
		.desc = "Network Info Request (Vendor-Specific)",
		.init_frame = init_empty_frame,
	}, {
		.mmtype = HPAV_MMTYPE_NW_INFO_CNF,
		.desc = "Network Info Confirm (Vendor-Specific)",
		.dump_frame = hpav_dump_network_info_confirm,
	}, {
		.mmtype = HPAV_MMTYPE_CP_RPT_REQ,
		.desc = "Check Points Request",
		.init_frame = hpav_init_check_points_request,
	}, {
		.mmtype = HPAV_MMTYPE_CP_RPT_IND,
		.desc = "Check Points Indicate",
		.dump_frame = hpav_dump_check_points_indicate,
	}, {
		.mmtype = HPAV_MMTYPE_FR_LBK_REQ,
		.desc = "Loopback Request",
		.init_frame = hpav_dump_loopback_request,
	}, {
		.mmtype = HPAV_MMTYPE_FR_LBK_CNF,
		.desc = "Loopback Confirm",
		.dump_frame = hpav_dump_loopback_confirm,
	}, {
		.mmtype = HPAV_MMTYPE_LBK_STAT_REQ,
		.desc = "Loopback Status Request",
		.init_frame = init_empty_frame,
	}, {
		.mmtype = HPAV_MMTYPE_LBK_STAT_CNF,
		.desc = "Loopback Status Confirm",
		.dump_frame = hpav_dump_loopback_status_confirm,
	}, {
		.mmtype = HPAV_MMTYPE_SET_KEY_REQ,
		.desc = "Set Encryption Key Request",
		.init_frame = hpav_init_set_enc_key_request,
	}, {
		.mmtype = HPAV_MMTYPE_SET_KEY_CNF,
		.desc = "Set Encryption Key Confirm",
		.dump_frame = hpav_dump_set_enc_key_confirm,
	}, {
		.mmtype = HPAV_MMTYPE_MFG_STRING_REQ,
		.desc = "Get Manufacturing String Request",
		.init_frame = init_empty_frame,
	}, {
		.mmtype = HPAV_MMTYPE_MFG_STRING_CNF,
		.desc = "Get Manufacturing String Confirm",
		.dump_frame = hpav_dump_get_manuf_string_confirm,
	}, {
		.mmtype = HPAV_MMTYPE_RD_CBLOCK_REQ,
		.desc = "Read Configuration Block Request",
		.init_frame = init_empty_frame,
	}, {
		.mmtype = HPAV_MMTYPE_RD_CBLOCK_CNF,
		.desc = "Read Configuration Block Confirm",
		.dump_frame = hpav_dump_read_config_block_confirm,
	}, {
		.mmtype = HPAV_MMTYPE_SET_SDRAM_REQ,
		.desc = "Set SDRAM Configuration Request",
	}, {
		.mmtype = HPAV_MMTYPE_SET_SDRAM_CNF,
		.desc = "Set SDRAM Configuration Confirm",
		.dump_frame = hpav_dump_set_sdram_config_confirm,
	}, {
		.mmtype = HPAV_MMTYPE_HOST_ACTION_IND,
		.desc = "Embedded Host Action Required Indicate",
	}, {
		.mmtype = HPAV_MMTYPE_HOST_ACTION_RSP,
		.desc = "Embedded Host Action Required Response",
	}, {
		.mmtype = HPAV_MMTYPE_OP_ATTR_REQ,
		.desc = "Get Device Attributes Request",
		.init_frame = hpav_init_get_devices_attrs_request,
	}, {
		.mmtype = HPAV_MMTYPE_OP_ATTR_CNF,
		.desc = "Get Device Attributes Confirm",
		.dump_frame = hpav_dump_get_devices_attrs_confirm,
	}, {
		.mmtype = HPAV_MMTYPE_GET_ENET_PHY_REQ,
		.desc = "Get Ethernet PHY Settings Request",
		.init_frame = hpav_init_get_enet_phy_settings_request,
	}, {
		.mmtype = HPAV_MMTYPE_GET_ENET_PHY_CNF,
		.desc = "Get Ethernet PHY Settings Confirm",
		.dump_frame = hpav_dump_get_enet_phy_settings_confirm,
	}, {
		.mmtype = HPAV_MMTYPE_TONE_MAP_REQ,
		.desc = "Get Tone Map Caracteristics Request",
		.init_frame = hpav_init_get_tone_map_charac_request,
	}, {
		.mmtype = HPAV_MMTYPE_TONE_MAP_CNF,
		.desc = "Get Tone Map Characteristics Confirm",
		.dump_frame = hpav_dump_get_tone_map_charac_confirm,
	}
};

/* HomePlug 1.0 frame operations */

static int hp10_init_channel_estimation_request(void *buf, int len, void *UNUSED(user))
{
	int avail = len;
	struct hp10_channel_estimation_request *mm = buf;

	mm->version = 0;

	avail -= sizeof(*mm);

	return (len - avail);
}

static int hp10_dump_parameters_stats_confirm(void *buf, int len)
{
	int avail = len;
	struct hp10_parameters_stats_confirm *mm = buf;

	faifa_printf(out_stream, "Tx ACK counter: %d\n", mm->tx_ack_cnt);
	faifa_printf(out_stream, "Tx NACK counter: %d\n", mm->tx_nack_cnt);
	faifa_printf(out_stream, "Tx FAIL counter: %d\n", mm->tx_fail_cnt);
	faifa_printf(out_stream, "Tx Contention loss counter: %d\n", mm->tx_cont_loss_cnt);
	faifa_printf(out_stream, "Tx Collision counter: %d\n", mm->tx_coll_cnt);
	faifa_printf(out_stream, "Tx CA3 counter: %d\n", mm->tx_ca3_cnt);
	faifa_printf(out_stream, "Tx CA2 counter: %d\n", mm->tx_ca2_cnt);
	faifa_printf(out_stream, "Tx CA1 counter: %d\n", mm->tx_ca1_cnt);
	faifa_printf(out_stream, "Tx CA0 counter: %d\n", mm->tx_ca0_cnt);
	faifa_printf(out_stream, "Rx cumul (bytes per 40-symbol packet counter: %d\n",
		mm->rx_cumul);

	avail -= sizeof(*mm);

	return (len - avail);
}

static void hp10_dump_tonemap(struct hp10_tonemap *tonemap)
{
	int i;

	for (i = 0; i < HP10_NUM_TONE_MAP; i++) {
		faifa_printf(out_stream, "Network DA");
		dump_hex(tonemap->netw_da, ETHER_ADDR_LEN, " "); faifa_printf(out_stream, "\n");
		faifa_printf(out_stream, "Number of 40-bytes symbols: %d\n", tonemap->bytes40);
		faifa_printf(out_stream, "Number of failed symbols: %d\n", tonemap->fails);
		faifa_printf(out_stream, "Number of droppe symbols: %d\n", tonemap->drops);
	}
}

static int hp10_dump_extended_network_stats(void *buf, int len)
{
	int avail = len;
	struct hp10_network_stats_confirm *mm = buf;

	faifa_printf(out_stream, "AC flag: %s\n", mm->ac ? "Yes" : "No");
	faifa_printf(out_stream, "Number of 40-symbol robo: %d\n", mm->bytes40_robo);
	faifa_printf(out_stream, "Number of failed robo: %d\n", mm->fails_robo);
	faifa_printf(out_stream, "Number of dropped robo: %d\n", mm->drops_robo);
	hp10_dump_tonemap(mm->nstone);

	avail -= sizeof(*mm);

	return (len - avail);
}

struct hp10_frame_ops hp10_frame_ops[] = {
	{
		.mmtype = 0x00,
		.desc = "Channel Estimation Request",
		.init_frame = hp10_init_channel_estimation_request,
	}, {
		.mmtype = 0x01,
		.desc = "Channel Estimation Confirm",
	}, {
		.mmtype = 0x04,
		.desc = "Set Network Encryption Key Request",
		.init_frame = init_empty_frame,
	}, {
		.mmtype = 0x06,
		.desc = "Set Network Encryption Key Confirm",
	}, {
		.mmtype = 0x07,
		.desc = "Parameters and Statistics Request",
		.init_frame = init_empty_frame,
	}, {
		.mmtype = 0x08,
		.desc = "Parameters and Statistics Confirm",
		.dump_frame = hp10_dump_parameters_stats_confirm,
	}, {
		.mmtype = 0x19,
		.desc = "Set Local parameters Request",
		.init_frame = init_empty_frame,
	}, {
		.mmtype = 0x1a,
		.desc = "Basic Network Statistics Confirm",
	}, {
		.mmtype = 0x1c,
		.desc = "Extended Network Statistics Confirm",
		.dump_frame = hp10_dump_extended_network_stats,
	}, {
		.mmtype = 0x1d,
		.desc = "Set Local Overrides Request",
		.init_frame = init_empty_frame,
	}, {
		.mmtype = 0x1e,
		.desc = "Bridging Characteristics Response",
	}, {
		.mmtype = 0x1f,
		.desc = "Set Transmit Characteristics Request",
	}
};

/**
 * set_oui - sets the OUI of a frame
 * @raw:	buffer to set the oui to
 * @oui:	value of the oui
 */
static inline void set_oui(void *raw, u_int8_t *oui)
{
	bcopy(oui, raw, 3);
}

/**
 * hpav_mmtype2index - lookup the mmtype and returns the corresponding
 * 		  index (if found) from the hpav_frame_ops array
 * @mmtype:	mmtype to look for
 */
static int hpav_mmtype2index(u_int16_t mmtype)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(hpav_frame_ops); i++) {
		if (hpav_frame_ops[i].mmtype == mmtype)
			return i;
	}

	return -1;
}

/**
 * hp10_mmtype2index - lookup the mmtype and returns the corresponding
 * 		  index (if found) from the hp10_frame_ops array
 * @mmtype:	mmtype to look for
 */
static int hp10_mmtype2index(u_int8_t mmtype)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(hp10_frame_ops); i++) {
		if (hp10_frame_ops[i].mmtype == mmtype)
			return i;
	}

	return -1;
}

/**
 * set_init_callback - set the new initialisation callback in frame_ops
 * @mmtype:	mmtype to set the new callback for
 * @callback:	the new callback
 */

int set_init_callback(u_int16_t mmtype, int (*callback)(void *buf, int len, void *user))
{
	int i;

	i = hpav_mmtype2index(mmtype);
	if (i < 0)
		return -1;

	if (callback)
		hpav_frame_ops[i].init_frame = callback;

	return 0;
}

/**
 * set_dump_callback - set the new dump callback in frame_ops
 * @mmtype:	mmtype to set the new callback for
 * @callback:	the new callback
 */

int set_dump_callback(u_int16_t mmtype, int (*callback)(void *buf, int len, struct ether_header *hdr))
{
	int i;

	i = hpav_mmtype2index(mmtype);
	if (i < 0)
		return -1;

	if (callback)
		hpav_frame_ops[i].dump_frame = callback;

	return 0;
}

/**
 * ether_init_header - initialize the Ethernet frame header
 * @buf:      buffer to initialize
 * @len:      size of the buffer
 * @da:        destination MAC address (should not be NULL)
 * @sa:        destination MAC address (should not be NULL)
 * @ethertype: ethertype (between HomePlug 1.0/AV)
 * @return:    number of bytes set in buffer
*/
int ether_init_header(void *buf, int len, u_int8_t *da, u_int8_t *sa, u_int16_t ethertype)
{
	int avail = len;
	struct ether_header *header = buf;

	/* set destination eth addr */
	memcpy(header->ether_dhost, da, ETHER_ADDR_LEN);

	/* set source eth addr */
	if (sa != NULL) {
		memcpy(header->ether_shost, sa, ETHER_ADDR_LEN);
	} else if (ethertype == ETHERTYPE_HOMEPLUG) {
		memset(header->ether_shost, 0xFF, ETHER_ADDR_LEN);
	} else if (ethertype == ETHERTYPE_HOMEPLUG_AV) {
		memset(header->ether_shost, 0x00, ETHER_ADDR_LEN);
	}

	/* Set the ethertype */
	header->ether_type = htons(ethertype);

	avail -= sizeof(*header);

	return (len - avail);
}

static const char *hpav_get_mmver_str(u_int8_t mmver)
{
	if( mmver == HPAV_VERSION_1_0 )
		return "1.0";
	else if( mmver == HPAV_VERSION_1_1 )
		return "1.1";
	else
		return "Unknown";
}

/**
 * hpav_do_frame - prepare and send a HomePlug AV frame to the network
 * @frame_buf:	data buffer
 * @frame_len:	data buffer length
 * @mmtype:	MM type to send
 * @da:		destination MAC address
 * @sa:		source MAC address
 * @user:	user buffer
 */
static int hpav_do_frame(void *frame_buf, int frame_len, u_int16_t mmtype, u_int8_t *da, u_int8_t *sa, void *user)
{
	int i, n;
	struct hpav_frame *frame;
	u_int8_t *frame_ptr = frame_buf;

	/* Lookup for the index from the mmtype */
	i = hpav_mmtype2index(mmtype);
	if (i < 0) {
		faifa_printf(err_stream, "Invalid MM Type %04hx\n", mmtype);
		return -1;
	}

	/* Zero-fill the frame */
	bzero(frame_buf, frame_len);

	/* Check the destination MAC address */
	if (da == NULL || faifa_is_zero_ether_addr(da))
		da = hpav_intellon_macaddr;

	/* Set the ethernet frame header */
	n = ether_init_header(frame_ptr, frame_len, da, sa, ETHERTYPE_HOMEPLUG_AV);
	frame_len -= n;
	frame_ptr += n;

	frame = (struct hpav_frame *)frame_ptr;
	n = sizeof(frame->header);
	frame->header.mmtype = STORE16_LE(mmtype);
	if( (mmtype & HPAV_MM_CATEGORY_MASK) == HPAV_MM_VENDOR_SPEC ) {
		frame->header.mmver = HPAV_VERSION_1_0;
		set_oui(frame->payload.vendor.oui, hpav_intellon_oui);
		n += sizeof(frame->payload.vendor);
	} else {
		frame->header.mmver = HPAV_VERSION_1_1;
		n += sizeof(frame->payload.pub);
	}
	frame_len -= n;
	frame_ptr += n;

	faifa_printf(out_stream, "Frame: %s (0x%04hX)\n", hpav_frame_ops[i].desc,
						hpav_frame_ops[i].mmtype);

	/* Call the frame specific setup callback */
	if (hpav_frame_ops[i].init_frame != NULL) {
		n = hpav_frame_ops[i].init_frame(frame_ptr, frame_len, user);
		frame_ptr += n;
		frame_len = frame_ptr - (u_int8_t *)frame_buf;
	}
	return (frame_len);
}

/**
 * hp10_do_frame - prepare and send a HomePlug 1.0 frame to the network
 * @frame_buf:	data buffer
 * @frame_len:	data buffer length
 * @mmtype:	MM type to send
 * @da:		destination MAC address
 * @sa:		source MAC address
 * @user:	user buffer
 */
static int hp10_do_frame(u_int8_t *frame_buf, int frame_len, u_int8_t mmtype, u_int8_t *da, u_int8_t *sa, void *user)
{
	int i, n;
	struct hp10_frame *frame;
	u_int8_t *frame_ptr = frame_buf;

	/* Lookup for the index from the mmtype */
	i = hp10_mmtype2index(mmtype);
	if (i < 0) {
		faifa_printf(err_stream, "Invalid MM Type %04hx\n", mmtype);
		return -1;
	}

	/* Zero-fill the frame */
	bzero(frame_ptr, frame_len);

	/* Check the destination MAC address */
	if (da == NULL)
		da = broadcast_macaddr;

	/* Set the ethernet frame header */
	n = ether_init_header(frame_ptr, frame_len, broadcast_macaddr, sa, ETHERTYPE_HOMEPLUG);
	frame_len -= n;
	frame_ptr += n;

	frame = (struct hp10_frame *)frame_ptr;
	n = sizeof(struct hp10_frame) + sizeof(struct hp10_mmentry);
	frame_len -= n;
	frame_ptr += n;

	/* Initialize the frame header with the specificied mmtype */
	frame->mmecount = 1;
	frame->mmentries[0].mmetype = (u_int8_t)mmtype;
	frame->mmentries[0].mmeversion = 0;
	frame->mmentries[0].mmelength = 0;

	faifa_printf(out_stream, "Frame: 0x%02hX (%s)\n",
		hp10_frame_ops[i].mmtype, hp10_frame_ops[i].desc);

	/* Call the frame specific setup callback */
	if (hp10_frame_ops[i].init_frame != NULL) {
		n = hp10_frame_ops[i].init_frame(frame_ptr, frame_len, user);
		frame_ptr += n;
		frame_len = frame_ptr - (u_int8_t *)frame_buf;
		frame->mmentries[0].mmelength += n;
	}

	return (frame_len);
}

/**
 * do_frame - Send a HomePlug 1.0/AV frame
 * @mmtype: MM type to send
 * @da:	    destination MAC address (NULL for broadcast)
 * @sa:	    source MAC address (NULL for broadcast)
 */
int do_frame(faifa_t *faifa, u_int16_t mmtype, u_int8_t *da, u_int8_t *sa, void *user)
{
	u_int8_t frame_buf[1518];
	int frame_len = sizeof(frame_buf);
	int i;

	/* Dispatch the frame construction */
	if ((i = hpav_mmtype2index(mmtype)) >= 0)
		frame_len = hpav_do_frame(frame_buf, frame_len, mmtype, da, sa, user);
	else if ((i = hp10_mmtype2index(mmtype)) >= 0)
		frame_len = hp10_do_frame(frame_buf, frame_len, mmtype, da, sa, user);

	if (i < 0)
		return -1;

	if (frame_len < ETH_ZLEN)
		frame_len = ETH_ZLEN;

	/* Dump the frame on the screen for debugging purposes */
	if (faifa->verbose)
		dump_hex_blob(faifa, frame_buf, frame_len);

	frame_len = faifa_send(faifa, frame_buf, frame_len);
	if (frame_len == -1)
		faifa_printf(err_stream, "Init: error sending frame (%s)\n", faifa_error(faifa));

	return frame_len;
}

/**
 * hpav_dump_frame - Parse an HomePlug AV frame
 * @frame_ptr:	packet data
 * @frame_len:	packet length
 */
static int hpav_dump_frame(u_int8_t *frame_ptr, int frame_len, struct ether_header *hdr)
{
	struct hpav_frame *frame = (struct hpav_frame *)frame_ptr;
	int i;

	if( (i = hpav_mmtype2index(STORE16_LE(frame->header.mmtype))) < 0 ) {
		faifa_printf(out_stream, "\nUnknow MM type : %04hX\n", frame->header.mmtype);
		return 0;
	}

	faifa_printf(out_stream, "Frame: %s (%04hX), HomePlug-AV Version: %s\n",
		hpav_frame_ops[i].desc, hpav_frame_ops[i].mmtype,
		hpav_get_mmver_str(frame->header.mmver));

	if( (frame->header.mmtype & HPAV_MM_CATEGORY_MASK) == HPAV_MM_VENDOR_SPEC ) {
		frame_ptr = frame->payload.vendor.data;
		frame_len -= sizeof(frame->payload.vendor);
	} else {
		frame_ptr = frame->payload.pub.data;
		frame_len -= sizeof(frame->payload.pub);
	}

	/* Call the frame specific dump callback */
	if (hpav_frame_ops[i].dump_frame != NULL)
		frame_ptr += hpav_frame_ops[i].dump_frame(frame_ptr, frame_len, hdr);

	return (frame_ptr - (u_int8_t *)frame);
}

/**
 * hp10_dump_frame - Parse an HomePlug 1.0 frame
 * @frame_ptr:	packet data
 * @frame_len:	packet length
 */
static int hp10_dump_frame(u_int8_t *frame_ptr, int UNUSED(frame_len))
{
	struct hp10_frame *frame = (struct hp10_frame *)frame_ptr;
	unsigned int mmeindex;
	unsigned int mmecount = frame->mmecount;
	struct hp10_mmentry *mmentry;
	int i;

	frame_ptr += sizeof(struct hp10_frame);

	for (mmeindex = 0; mmeindex < mmecount; mmeindex++) {
		mmentry = (struct hp10_mmentry *)frame_ptr;
		faifa_printf(out_stream, "Frame: 0x%02hhX (",
			mmentry->mmetype);
		frame_ptr += sizeof(struct hp10_mmentry);
		if ((i = hp10_mmtype2index(mmentry->mmetype)) >= 0) {
			faifa_printf(out_stream, "%s)\n", hp10_frame_ops[i].desc);
			if (hp10_frame_ops[i].dump_frame != NULL) {
				hp10_frame_ops[i].dump_frame(mmentry->mmedata, mmentry->mmelength);
			}
		} else {
			faifa_printf(out_stream, "unknown)\n");
		}
		frame_ptr += mmentry->mmelength;
	}

	return (frame_ptr - (u_int8_t *)frame);
}

/**
 * do_receive_frame - Receive a frame from the network
 * @args:	unused
 * @hdr:	unused
 * @packet:	received packet
 */
void do_receive_frame(faifa_t *faifa, void *buf, int len, void *UNUSED(user))
{
	struct ether_header *eth_header = buf;
	u_int16_t *eth_type = &(eth_header->ether_type);
	u_int8_t *frame_ptr = (u_int8_t *)buf, *payload_ptr;
	int frame_len = len, payload_len;

	payload_ptr = frame_ptr + sizeof(*eth_header);
	payload_len = frame_len - sizeof(*eth_header);
	if (*eth_type == ETHERTYPE_8021Q) {
		payload_ptr += 4;
		payload_len -= 4;
		eth_type = (u_int16_t *)(payload_ptr - 2);
	}

	/* Check ethertype */
	if (!(*eth_type == ntohs(ETHERTYPE_HOMEPLUG)) && !(*eth_type == ntohs(ETHERTYPE_HOMEPLUG_AV)))
		return;

	faifa_printf(out_stream, "\nDump:\n");

	if (*eth_type == ntohs(ETHERTYPE_HOMEPLUG))
		hp10_dump_frame(payload_ptr, payload_len);
	else if (*eth_type == ntohs(ETHERTYPE_HOMEPLUG_AV))
		hpav_dump_frame(payload_ptr, payload_len, eth_header);

	/* Dump the frame on the screen for debugging purposes */
	if (faifa->verbose)
		dump_hex_blob(faifa, frame_ptr, frame_len);
}

/**
 * open_pcap_loop - open a network interface in PCAP loop mode
 * @arg:	unused
 */
void *receive_loop(faifa_t *faifa)
{
	faifa_loop(faifa, (void *)do_receive_frame, faifa);

	return faifa;
}

/**
 * ask_for_frame - ask the user for a specific mmtype
 * @mmtype:	mmtype to store the user input
 */
static int ask_for_frame(u_int16_t *mmtype)
{
	unsigned int i;

	faifa_printf(out_stream, "\nSupported HomePlug AV frames\n\n");
	faifa_printf(out_stream, "type   description\n");
	faifa_printf(out_stream, "------ -----------\n");
	for (i = 0; i < ARRAY_SIZE(hpav_frame_ops); i++) {
		if (hpav_frame_ops[i].init_frame != NULL) {
			faifa_printf(out_stream, "0x%04hX %s\n", hpav_frame_ops[i].mmtype, hpav_frame_ops[i].desc);
		}
	}
	faifa_printf(out_stream, "\nSupported HomePlug 1.0 frames\n\n");
	faifa_printf(out_stream, "type   description\n");
	faifa_printf(out_stream, "------ -----------\n");
	for (i = 0; i < ARRAY_SIZE(hp10_frame_ops); i++) {
		if (hp10_frame_ops[i].init_frame != NULL) {
			faifa_printf(out_stream, "0x%04hX %s\n", hp10_frame_ops[i].mmtype, hp10_frame_ops[i].desc);
		}
	}
	faifa_printf(out_stream, "\nChoose the frame type (Ctrl-C to exit): 0x");
	fscanf(in_stream, "%4x", &i);
	*mmtype = (u_int16_t)(0xFFFF & i);

	return (*mmtype != 0xFFFF);
}


/**
 * menu - show a menu of the available to send mmtypes
 */
void menu(faifa_t *faifa)
{
	pthread_t receive_thread;
	u_int16_t mmtype;

	/* Create a receiving thread */
	if (pthread_create(&receive_thread, NULL, (void *)receive_loop, faifa)) {
		perror("error creating thread");
		abort();
	}
	faifa_printf(out_stream, "Started receive thread\n");

	/* Keep asking the user for a mmtype to send */
	while (ask_for_frame(&mmtype)) {
		do_frame(faifa, mmtype, faifa->dst_addr, NULL, NULL);
		sleep(1);
	}

	/* Rejoin the receiving thread */
	if (pthread_join(receive_thread, NULL)) {
		perror("error joining thread");
		abort();
	}
	faifa_printf(out_stream, "Closing receive thread\n");
}
