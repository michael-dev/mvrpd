/**
 *  This file is part of mvrpd.
 *
 *  mvrpd is free software: you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  mvrpd is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with mvrpd.
 *  If not, see <http://www.gnu.org/licenses/>.
 *
 *  (C) 2019, Michael Braun <michael-dev@fami-braun.de>
 */

#include "config.h"
#include "event.h"
#include "debug.h"
#include "cmdline.h"
#include "timer.h"

#include <sys/types.h>
#include <net/if.h>
#define _LINUX_IF_H
#include <linux/netfilter/nfnetlink_log.h>
#include <netlink/netfilter/nfnl.h>
#include <netlink/netfilter/log.h>
#include <netlink/netfilter/log_msg.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <errno.h>
#include <assert.h>

static int groupId = NFLOG_GROUP;

static void obj_input_nflog(struct nl_object *obj, void *arg)
{
	struct nfnl_log_msg *msg = (struct nfnl_log_msg *) obj;
	char ifname[IF_NAMESIZE];

	if (isdebug(DEBUG_NFLOG)) {
		char buf[4096];
		nl_object_dump_buf(obj, buf, sizeof(buf));
		eprintf(DEBUG_NFLOG,  "received #2 %s", buf);
	}

	uint32_t indev = nfnl_log_msg_get_physindev(msg);
	if (!indev)
		indev = nfnl_log_msg_get_indev(msg);

	if (indev == 0) {
		eprintf(DEBUG_NFLOG,  "obj_input_nflog...err indev %d == 0", indev);
		return;
	}
	memset(ifname,0,sizeof(ifname));
	if (!if_indextoname(indev, ifname)) {
		eprintf(DEBUG_ERROR,  "obj_input_nlog: failed to fetch interface name of ifidx %d: %s (%d)", indev, strerror(errno), errno);
		return;
	}

	uint16_t hwproto = ntohs(nfnl_log_msg_get_hwproto(msg));
	if (hwproto != 0x88f5) {
		eprintf(DEBUG_ERROR,  "obj_input_nlog: not MVRP protocol: hwproto = %x on %s(%d)", hwproto, ifname, indev);
		return;
	}

	int len = 0;
	const u_char* data = (const u_char*) nfnl_log_msg_get_payload(msg, (int*) &len);

	if (isdebug(DEBUG_NFLOG)) {
		eprintf(DEBUG_NFLOG,  "obj_input...packet received proto=%x on %s(%d)", hwproto, ifname, indev);
		fprintf(stderr, "payload = ");
		for (int i = 0; i < len; i++)
		{
			fprintf(stderr, "%s%02x", (i > 0 ? ":" : ""),  data[i]);
		}
		fprintf(stderr, "\n");
	}

	cb_call_packet_cb(hwproto, data, len, ifname, indev);
}

static int event_input_nflog(struct nl_msg *msg, void *arg)
{
	if (isdebug(DEBUG_NFLOG)) {
		char buf[4096] = {0};
		FILE *ofd;

		ofd = fmemopen(buf, sizeof(buf), "w");
		if (ofd) {
			nl_msg_dump(msg, ofd);
			fclose(ofd);
			eprintf(DEBUG_NFLOG,	"received message #2: %s", buf);
		} else {
			eprintf(DEBUG_NFLOG,	"received message #2");
		}

		/* get hw header: <src-mac><dst-mac><00 08 aka ip> -> no VLAN */
		struct nlattr *attr = nlmsg_find_attr(nlmsg_hdr(msg), NFNL_HDRLEN, NFULA_HWHEADER);
		char *data = nla_data(attr);
		int len = nla_len(attr);
		memset(buf, 0, sizeof(buf));
		int offset = 0;
		for (int i = 0; i < len && offset < sizeof(buf); i++)
			offset += snprintf(buf + offset, sizeof(buf) - offset, (i > 0 ? ":%02hhx" : "%02hhx"), data[i]);
		eprintf(DEBUG_NFLOG,	"HWHEADER %s", buf);

	}
	if (nl_msg_parse(msg, &obj_input_nflog, NULL) < 0)
		eprintf(DEBUG_NFLOG,  "<<EVENT:nflog>> Unknown message type");
	return NL_OK;
}

static void nflog_receive(int s, void* ctx)
{
	int ret;
	struct nl_sock *nf_sock_nflog = (struct nl_sock *) ctx;
	ret = nl_recvmsgs_default(nf_sock_nflog);
	if (ret < 0) {
		eprintf(DEBUG_ERROR, "receiving nflog socket %d failed %s", s, strerror(errno));
	}
}

static void set_nflog_group(int c, void *arg) {
	if (!optarg)
		return;

	groupId = atoi(optarg);
	fprintf(stderr, "nf log group %d\n", groupId);
}

static void nflog_start_listen(void *ctx) {
	/* connect to netfilter / NFLOG */
	struct nl_sock *nf_sock_nflog;
	struct nfnl_log *log;
	int nffd;
	int rcvbuf;

	eprintf(DEBUG_NFLOG, "listen to NFLOG packets for group %d", groupId);

	nf_sock_nflog = nl_socket_alloc();
	if (nf_sock_nflog == NULL) {
		eprintf(DEBUG_ERROR, "cannot alloc socket: %s", strerror(errno));
		exit(254);
	}
	nl_socket_disable_seq_check(nf_sock_nflog);
	nl_socket_modify_cb(nf_sock_nflog, NL_CB_VALID, NL_CB_CUSTOM, event_input_nflog, NULL);

	if (nl_connect(nf_sock_nflog, NETLINK_NETFILTER) < 0) {
		eprintf(DEBUG_ERROR, "cannot connect: %s", strerror(errno));
		exit(254);
	}

	if (nfnl_log_pf_bind(nf_sock_nflog, AF_BRIDGE) < 0) {
		eprintf(DEBUG_ERROR, "cannot bind: %s", strerror(errno));
		exit(254);
	}

	log = nfnl_log_alloc();
	assert(log);
	nfnl_log_set_group(log, groupId);

	nfnl_log_set_copy_mode(log, NFNL_LOG_COPY_PACKET);

	nfnl_log_set_copy_range(log, 0xFFFF);

	if (nfnl_log_create(nf_sock_nflog, log) < 0) {
		eprintf(DEBUG_ERROR, "cannot create log: %s", strerror(errno));
		exit(254);
	}

	nffd = nl_socket_get_fd(nf_sock_nflog);
	if (nffd < 0) {
		eprintf(DEBUG_ERROR, "nflog socket %d is error", nffd);
		exit(254);
	}
	eprintf(DEBUG_NFLOG, "nflog socket %d", nffd);

	rcvbuf = 1024 * 1024;
	if (setsockopt(nffd, SOL_SOCKET, SO_RCVBUFFORCE,
	               &rcvbuf, sizeof rcvbuf)) {
		eprintf(DEBUG_ERROR, "nflog socket %d cannot set buffer size to %d", nffd, rcvbuf);
	}

	cb_add_handle(nffd, nf_sock_nflog, nflog_receive);
}

static __attribute__((constructor)) void nflog_init()
{
	{
		struct option long_option = {"nflog-group", required_argument, 0, 0};
		add_option_cb(long_option, set_nflog_group, NULL);
	}

	cb_add_timer(0, 0, NULL, nflog_start_listen);
}

