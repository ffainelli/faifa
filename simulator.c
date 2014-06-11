/*
 * Homeplug AV INT6x00 simulator device
 *
 * Copyright (C) 2012, Florian Fainelli <florian@openwrt.org>
 *
 * this device mimics the behavior of a Qualcomm/Atheros/Intellon INT6x00
 * device and will answer to the frames sent to it
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
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>

#include <linux/if_ether.h>

#include <event2/event-config.h>
#include <event2/event.h>
#include <event2/util.h>

#include "homeplug_av.h"

struct context {
	struct event_base *ev;
	struct event *read_ev;
	int sock_fd;
	const char *iface;
	int if_index;
};

static int sim_send_pkt(struct context *ctx, const uint8_t *to,
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

static int sim_send_vendor_pkt(struct context *ctx, const uint8_t *to,
				uint16_t mmtype, const void *payload, size_t payload_len)
{
	struct homeplug_av_vendor_hdr hdr;

	memset(&hdr, 0, sizeof(hdr));
	hdr.mmver = 0;
	hdr.mmtype = mmtype;
	hdr.oui[0] = 0x00;
	hdr.oui[1] = 0xB0;
	hdr.oui[2] = 0x52;

	return sim_send_pkt(ctx, to, &hdr, sizeof(hdr), payload, payload_len);
}

static void sim_read_cb(evutil_socket_t fd, short flags, void *argv)
{
	struct context *ctx = argv;
	char frame[ETH_DATA_LEN];
	ssize_t len;
	socklen_t lllen;
	struct sockaddr_ll ll;
	uint8_t *from;
	struct hpav_frame_header *hdr;
	const void *payload = NULL;
	size_t payload_size = 0;
	uint8_t qca_bcast[ETH_ALEN] = { 0x00, 0xB0, 0x52, 0x00, 0x00, 0x00 };
	int ret;


	lllen = sizeof(ll);
	len = recvfrom(ctx->sock_fd, frame, sizeof(frame), 0,
			(struct sockaddr *)&ll, &lllen);
	if (len < 0 || len < HPAV_MIN_FRAMSIZ) {
		if (errno != EAGAIN)
			perror("recvfrom");
		return;
	}

	from = ll.sll_addr;
	hdr = (struct hpav_frame_header *)frame;

	switch (hdr->mmtype) {
	case 0xA000:
		fprintf(stdout, "Get Software version\n");
		struct get_device_sw_version_confirm sw_confirm;

		memset(&sw_confirm, 0, sizeof(sw_confirm));
		sw_confirm.mstatus = 0;
		sw_confirm.device_id = INT6300_DEVICE_ID;
		sw_confirm.version_length = sizeof(sw_confirm.version);
		snprintf((char *)sw_confirm.version, sizeof(sw_confirm.version), "%s", "Faifa simulator");
		sw_confirm.upgradeable = 1;
		payload = &sw_confirm;
		payload_size = sizeof(sw_confirm);
		break;
	}

	if (!payload_size)
		return;

	ret = sim_send_vendor_pkt(ctx, qca_bcast, htole16(hdr->mmtype + 1),
				payload, payload_size);
	if (ret)
		fprintf(stdout, "failed to reply: %d\n", ret);
}

static int sim_init_ctx(struct context *ctx)
{
	int fd;
	int ret;
	struct sockaddr_ll ll;

	ctx->ev = event_base_new();
	if (!ctx->ev) {
		fprintf(stderr, "failed to create new libevent context\n");
		return -ENOMEM;
	}

	fd = socket(PF_PACKET, SOCK_DGRAM, htons(ETHERTYPE_HOMEPLUG_AV));
	if (fd < 0) {
		perror("socket");
		ret = fd;
		goto out;
	}

	ctx->if_index = if_nametoindex(ctx->iface);
	memset(&ll, 0, sizeof(ll));
	ll.sll_family = AF_PACKET;
	ll.sll_ifindex = ctx->if_index;
	ll.sll_protocol = htons(ETHERTYPE_HOMEPLUG_AV);

	ret = bind(fd, (struct sockaddr *)&ll, sizeof(ll));
	if (ret < 0) {
		perror("bind");
		goto out_close;
	}

	ctx->sock_fd = fd;

	/* setup libevent for polling this socket */
	ctx->read_ev = event_new(ctx->ev, fd, EV_READ | EV_PERSIST, sim_read_cb, ctx);
	if (!ctx->read_ev) {
		fprintf(stderr, "failed to create read event");
		ret = -EINVAL;
		goto out_close;
	}

	fprintf(stdout, "initialized RAW socket\n");

	event_add(ctx->read_ev, NULL);

	return 0;

out_close:
	close(fd);
out:
	event_base_free(ctx->ev);
	return ret;
}

static void sim_deinit_ctx(struct context *ctx)
{
	/* disable all events */
	event_base_free(ctx->ev);
}

static int sim_event_loop(struct context *ctx)
{
	event_base_dispatch(ctx->ev);

	return 0;
}

static void usage(const char *name)
{
	fprintf(stderr, "Usage %s [options] [interface]\n"
			"-h:	this help",
			name);
	exit(1);
}

int main(int argc, char **argv)
{
	int opt;
	struct context ctx;
	int ret;
	const char *appname = argv[0];
	const char *iface = NULL;

	memset(&ctx, 0, sizeof(ctx));

	while ((opt = getopt(argc, argv, "V:h")) > 0) {
		switch (opt) {
		case 'h':
		default:
			usage(appname);
			break;
		}
	}

	argv += optind;
	argc -= optind;

	ctx.iface = argv[0];
	if (!ctx.iface)
		usage(appname);

	ret = sim_init_ctx(&ctx);
	if (ret) {
		fprintf(stderr, "failed to initialize context\n");
		return ret;
	}

	ret = sim_event_loop(&ctx);
out:
	sim_deinit_ctx(&ctx);
	return ret;
}
