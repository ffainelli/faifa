/*
 * Lightweight Homeplug AV configuration utility
 *
 * Generates a NMK/DAK given their NPW and DPW
 *
 * Copyright (C) 2012, Florian Fainelli <florian@openwrt.org>
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <net/if.h>

#include <linux/if_ether.h>

#include "homeplug_av.h"
#include "crypto.h"

struct context {
	int sock_fd;
	int if_index;
};

static int send_pkt(struct context *ctx, const uint8_t *to,
			const void *hdr, size_t hdrlen,
			const void *payload, size_t payload_len)
{
	struct sockaddr_ll ll;
	struct msghdr msg;
	struct iovec iov[3];
	size_t total_len;
	uint8_t padding[64];
	int ret;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = iov;
	total_len = 0;

	iov[msg.msg_iovlen].iov_base = (void *)hdr;
	iov[msg.msg_iovlen].iov_len = hdrlen;
	total_len += hdrlen;
	msg.msg_iovlen = 1;

	if (payload_len) {
		iov[msg.msg_iovlen].iov_base = (void *)payload;
		iov[msg.msg_iovlen].iov_len = payload_len;
		total_len += payload_len;
		msg.msg_iovlen++;
	}

	if (total_len < 64) {
		memset(padding, 0, sizeof(padding));
		iov[msg.msg_iovlen].iov_base = (void *)padding;
		iov[msg.msg_iovlen].iov_len = 64 - total_len;
		msg.msg_iovlen++;
	}

	memset(&ll, 0, sizeof(ll));
	ll.sll_family = AF_PACKET;
	ll.sll_ifindex = ctx->if_index;
	ll.sll_protocol = htons(ETHERTYPE_HOMEPLUG_AV);

	memcpy(ll.sll_addr, to, ETH_ALEN);
	msg.msg_name = &ll;
	msg.msg_namelen = sizeof(ll);

	ret = sendmsg(ctx->sock_fd, &msg, 0);
	if (ret < 0) {
		if (errno != EAGAIN)
			perror("sendmsg");
		return ret;
	}

	return 0;
}

struct homeplug_av_vendor_hdr {
	uint8_t mmver;
	uint16_t mmtype;
	uint8_t oui[3];
} __attribute__((__packed__));

static int send_vendor_pkt(struct context *ctx, const uint8_t *to,
				uint16_t mmtype, const void *payload, size_t payload_len)
{
	struct homeplug_av_vendor_hdr hdr;

	memset(&hdr, 0, sizeof(hdr));
	hdr.mmver = 0;
	hdr.mmtype = mmtype;
	hdr.oui[0] = 0x00;
	hdr.oui[1] = 0xB0;
	hdr.oui[2] = 0x52;

	return send_pkt(ctx, to, &hdr, sizeof(hdr), payload, payload_len);
}

static int init_socket(struct context *ctx, const char *iface)
{
	int ret;
	struct sockaddr_ll ll;

	ctx->sock_fd = socket(PF_PACKET, SOCK_DGRAM, htons(ETHERTYPE_HOMEPLUG_AV));
	if (ctx->sock_fd < 0) {
		perror("socket");
		return -1;
	}

	ctx->if_index = if_nametoindex(iface);
	memset(&ll, 0, sizeof(ll));
	ll.sll_family = AF_PACKET;
	ll.sll_ifindex = ctx->if_index;
	ll.sll_protocol = htons(ETHERTYPE_HOMEPLUG_AV);

	ret = bind(ctx->sock_fd, (struct sockaddr *)&ll, sizeof(ll));
	if (ret < 0) {
		perror("bind");
		goto out_close;
	}

	return 0;

out_close:
	close(ctx->sock_fd);
	return ret;
}

static uint8_t bcast_hpav_mac[ETH_ALEN] = { 0x00, 0xB0, 0x52, 0x00, 0x00, 0x01 };

static int send_key(struct context *ctx, const char *npw,
			const char *dpw, const uint8_t mac[ETH_ALEN])
{
	struct set_encryption_key_request key_req;
	uint8_t key[16];

	memset(&key_req, 0, sizeof(key_req));

	key_req.peks = 0x01;

	gen_passphrase(npw, key, nmk_salt);
	memcpy(key_req.nmk, key, AES_KEY_SIZE);
	key_req.peks_payload = NO_KEY;

	if (dpw) {
		gen_passphrase(dpw, key, dak_salt);
		memcpy(key_req.dak, key, AES_KEY_SIZE);
		key_req.peks_payload = DST_STA_DAK;
	}

	memcpy(key_req.rdra, mac, ETH_ALEN);

	return send_vendor_pkt(ctx, mac, HPAV_MMTYPE_SET_KEY_REQ,
				&key_req, sizeof(key_req));

}




static int read_key_confirm(struct context *ctx, const uint8_t mac[ETH_ALEN])
{
	uint8_t frame[ETH_DATA_LEN];
	ssize_t len;
	socklen_t sk_len;
	struct sockaddr_ll ll;
	struct hpav_frame *hpav_frame;
	uint8_t status;
	uint8_t *from;

	sk_len = sizeof(ll);
	len = recvfrom(ctx->sock_fd, frame, sizeof(frame), 0,
			(struct sockaddr *)&ll, &sk_len);
	if (len < 0 || len < HPAV_MIN_FRAMSIZ) {
		if (errno != EAGAIN)
			perror("recvfrom");
		return len;
	}

	from = ll.sll_addr;

	/* destination MAC is different from broadcast HomePlug AV MAC
	 * and source MAC is different form destination MAC
	 */
	if (memcmp(mac, bcast_hpav_mac, ETH_ALEN) &&
	    memcmp(mac, from, ETH_ALEN)) {
		fprintf(stderr, "spurious reply from another station\n");
		return 1;
	}

	hpav_frame = (struct hpav_frame *)frame;
	if (le16toh(hpav_frame->header.mmtype) != HPAV_MMTYPE_SET_KEY_CNF)
		return 1;

	status = hpav_frame->payload.vendor.data[0];
	switch (status) {
	case KEY_SUCCESS:
		fprintf(stdout, "Success!!\n");
		return 0;
	case KEY_INV_EKS:
		fprintf(stderr, "Invalid EKS\n");
		return 1;
	case KEY_INV_PKS:
		fprintf(stderr, "Invalid PKS\n");
		return 1;
	default:
		fprintf(stderr, "unknown answer: 0x%02x\n", status);
	}

	return 0;
}



static int pushbutton_request(struct context *ctx, uint8_t mac)
{
	return send_vendor_pkt(ctx, mac, HPAV_MMTYPE_MS_PB_ENC,
					NULL, 0);
}


static int send_reset(struct context *ctx, uint8_t *mac)
{
	return send_vendor_pkt(ctx, mac, HPAV_MMTYPE_RS_DEV_REQ,
					NULL, 0);
}

static int generate_passphrase(struct context *ctx,
				const char *npw, const char *dpw)
{
	uint8_t key[16];
	int i;

	if (!npw && !dpw) {
		fprintf(stderr, "missing NPW and DPW\n");
		return 1;
	}

	if (npw)
		gen_passphrase(npw, key, nmk_salt);
	else
		gen_passphrase(dpw, key, dak_salt);

	for (i = 0; i < sizeof(key); i++)
		fprintf(stdout, "%02x", key[i]);

	return 0;
}

static void sighandler(int signo)
{
	if (signo == SIGALRM) {
		fprintf(stdout, "timeout reading answer from sta, exiting\n");
		exit(1);
	}
}

static void usage(void)
{
	fprintf(stderr, "Usage: hpav_cfg [options] interface\n"
			"-n:	NPW passphrase\n"
			"-d:	DPW passphrase\n"
			"-p:	same as -n (deprecated)\n"
			"-a:	device MAC address\n"
			"-r:	send a device reset\n"
			"-u:	PusbButton request\n"
			"-k:	hash only\n");
}

int main(int argc, char **argv)
{
	int opt;
	int ret;
	const char *mac_address = NULL;
	const char *npw = NULL;
	const char *dpw = NULL;
	const char *iface = NULL;
	struct context ctx;
	unsigned int hash_only = 0;
	unsigned int reset_device = 0;
	unsigned int push_button = 0;
	uint8_t mac[ETH_ALEN] = { 0 };

	memset(&ctx, 0, sizeof(ctx));

	while ((opt = getopt(argc, argv, "n:d:p:a:i:ukrh")) > 0) {
		switch (opt) {
		case 'n':
		case 'p':
			npw = optarg;
			break;
		case 'd':
			dpw = optarg;
			break;
		case 'a':
			mac_address = optarg;
			break;
		case 'i':
			iface = optarg;
			break;
		case 'k':
			hash_only = 1;
			break;
		case 'r':
			reset_device = 1;
			break;
		case 'u':
			push_button = 1;
			break;
		case 'h':
		default:
			usage();
			return 1;
		}
	}

	if (argc < 2) {
		usage();
		return 1;
	}

	argc -= optind;
	argv += optind;

	if (hash_only)
		return generate_passphrase(&ctx, npw, dpw);

	iface = argv[0];
	if (!iface) {
		fprintf(stderr, "missing interface argument\n");
		return 1;
	}


	fprintf(stdout, "Interface: %s\n", iface);

	if (mac_address) {
		ret = sscanf(mac_address,
			"%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8"",
			&mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
		if (ret != ETH_ALEN) {
			fprintf(stdout, "invalid MAC address\n");
			return ret;
		}
		fprintf(stdout, "MAC: %s\n", mac_address);
	} else {
		memcpy(mac, bcast_hpav_mac, sizeof(bcast_hpav_mac));
		fprintf(stdout, "MAC: using broadcast HPAV\n");
	}

	ret = init_socket(&ctx, iface);
	if (ret) {
		fprintf(stdout, "failed to initialize raw socket\n");
		return ret;
	}

	if (reset_device) {
		ret = send_reset(&ctx, mac);
		if (ret)
			fprintf(stdout, "failed to send reset\n");

		return ret;
	}


	if (push_button) {
		ret = pushbutton_request(&ctx, mac);
		fprintf(stdout, "sending PushButton request on the local link\n");
		if (ret)
			fprintf(stdout, "failed to send push_button\n");
		return ret;
	}


	if (!npw) {
		fprintf(stderr, "missing NPW argument\n");
		return 1;
	}

	fprintf(stdout, "NPW: %s\n", npw);
	ret = send_key(&ctx, npw, dpw, mac);
	if (ret) {
		fprintf(stdout, "failed to send key\n");
		return ret;
	}

	if (signal(SIGALRM, sighandler) == SIG_ERR) {
		fprintf(stdout, "failed to setup signal handler\n");
		return ret;
	}

	/* catch answer or timeout */
	alarm(3);

	ret = read_key_confirm(&ctx, mac);

	return ret;
}
