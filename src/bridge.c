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

#include <assert.h>
#include <linux/if_bridge.h>
#include <netlink/route/link.h>
#include <fnmatch.h>
#include <errno.h>

#include "debug.h"
#include "port.h"
#include "event.h"
#include "cmdline.h"
#include "timer.h"
#include "vlan.h"

#define ETH_ALEN 6
#ifndef VLAN_VID_MASK
#define VLAN_VID_MASK		0x0fff /* VLAN Identifier */
#endif

struct my_array {
	int num;
	char** item;
};

static struct my_array epIfPattern = { 0, NULL };
static struct my_array uplinkIfPattern = { 0, NULL };
static struct my_array ptpIfPattern = { 0, NULL };
static char *bridge = NULL;
static int bridgeIfIdx = 0;
static struct nl_sock *nf_sock_bcast = NULL;
static struct nl_sock *nf_sock_dump = NULL;
static struct nl_sock *nf_sock_vlan = NULL;
static int dumpNetlink = 0;

struct nf_obj_cb {
	struct nl_msg *msg;
	int fromDump;
};

static void bridge_dump_links();

static int
_br_vlan(int ifidx, int add, struct vlan_arr *vlan)
{
	assert(nf_sock_vlan);
	struct nl_msg *nlmsg = NULL;
	struct nlattr *af_spec = NULL;
	int err = -1;
	struct ifinfomsg ifi = { 0 };

	nlmsg = nlmsg_alloc_simple(add ? RTM_SETLINK : RTM_DELLINK, 0);
        if (!nlmsg)
		goto err;

	ifi.ifi_index = ifidx;
	ifi.ifi_family = AF_BRIDGE;
        if (nlmsg_append(nlmsg, &ifi, sizeof(ifi), NLMSG_ALIGNTO) < 0)
                goto err;

	af_spec = nla_nest_start(nlmsg, IFLA_AF_SPEC);
	if (!af_spec)
		goto err;

	int it = 0;
	uint16_t vid = 0;
	while (vlan_next(vlan, &it, &vid) == 0) {
		struct bridge_vlan_info vinfo = {};
		vinfo.vid = vid;
		if (nla_put(nlmsg, IFLA_BRIDGE_VLAN_INFO, sizeof(vinfo), &vinfo) < 0)
			goto err;
	}

	nla_nest_end(nlmsg, af_spec);

	err = nl_send_sync(nf_sock_vlan, nlmsg);
	nlmsg = NULL;

err:
	if (nlmsg)
		nlmsg_free(nlmsg);

	return err;
}

int br_vlan_add(int ifidx, struct vlan_arr *vlan)
{
	return _br_vlan(ifidx, 1, vlan);
}

int br_vlan_del(int ifidx, struct vlan_arr *vlan)
{
	return _br_vlan(ifidx, 0, vlan);
}

static int
in_array(const char *ifname, const struct my_array *arr)
{
	int i;

	assert(ifname);

	for (i = 0; i < arr->num; i++) {
		if (fnmatch(arr->item[i], ifname, 0) == 0) {
			return 1;
		}
	}

	return 0;
}


/* classify ifname
 * returns
 * 0: unclassified
 * 1: uplink
 * 2: ep
 */
static int
classify_ifname(const char *ifname)
{
	assert(ifname);

	if (in_array(ifname, &uplinkIfPattern))
		return 1;

	if (in_array(ifname, &epIfPattern))
		return 2;

	return 0;
}

static int
is_ptp(const char *ifname)
{
	return in_array(ifname, &ptpIfPattern);
}

static void
obj_input_newlink(struct rtnl_link *link, struct nl_msg *msg, int fromDump)
{
	const int ifidx = rtnl_link_get_ifindex(link);
	if (rtnl_link_get_master(link) != bridgeIfIdx &&
	   ifidx != bridgeIfIdx) {
		port_del(ifidx);
		return;
	}

	const char *ifname = rtnl_link_get_name(link);

	int type = classify_ifname(ifname);

	eprintf(DEBUG_BRIDGE, "NEWLINK: %s(%d) type %d", ifname, ifidx, type);

	if (type == 0 || (type == 1 && ifidx == bridgeIfIdx)) {
		port_del(ifidx);
		return;
	}

	struct ifinfomsg *ifi = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *a_af_spec = NULL;
	if (ifi->ifi_family != AF_BRIDGE) {
		eprintf(DEBUG_BRIDGE, "msg is not of family bridge, so discard IFLA_AF_SPEC");
		/* it might have IFLA_AF_SPEC, but this has a different content */
		if (!fromDump)
			bridge_dump_links(); // pass ifidx once the kernel supports it ;)
	} else {
		a_af_spec = nlmsg_find_attr(nlmsg_hdr(msg), sizeof(struct ifinfomsg), IFLA_AF_SPEC);
	}

	struct vlan_arr *vlan = vlan_alloc("br-newlink");

	if (a_af_spec) {
		eprintf(DEBUG_BRIDGE, "got IFLA_AF_SPEC type %d len %d, expecting type %d, fromDump %d", (int) nla_type(a_af_spec), (int) nla_len(a_af_spec), (int) IFLA_AF_SPEC, fromDump);

		int remaining;
		struct nlattr *attr;

    	    nla_for_each_nested(attr, a_af_spec, remaining) {
			eprintf(DEBUG_BRIDGE, "got anoter IFLA_AF_SPEC entry type %d len %d, expecting type %d and len %zd", (int) nla_type(attr), (int) nla_len(attr), (int) IFLA_BRIDGE_VLAN_INFO, sizeof(struct bridge_vlan_info));
			if (nla_type(attr) != IFLA_BRIDGE_VLAN_INFO)
				continue;
			if (nla_len(attr) != sizeof(struct bridge_vlan_info))
				continue;
			struct bridge_vlan_info *vinfo = nla_data(attr);
			if (!vinfo->vid || vinfo->vid >= VLAN_VID_MASK)
				continue;
			/* we do not care for BRIDGE_VLAN_INFO_RANGE_BEGIN as we did not ask for compressed VLAN information */
			if (vinfo->flags & (BRIDGE_VLAN_INFO_RANGE_BEGIN | BRIDGE_VLAN_INFO_RANGE_END)) {
				eprintf(DEBUG_ERROR,  "received compress vlan information");
				continue;
			}
			eprintf(DEBUG_BRIDGE, "found vlan %d on %s(%d)", vinfo->vid, ifname, ifidx);
			vlan_set(vlan, vinfo->vid);
		}
	} else {
		eprintf(DEBUG_BRIDGE, "bridge received no VLAN information");
	}

	if (isdebug(DEBUG_BRIDGE)) {
		char vlans[4096];
		int trunc = (sizeof(vlans) == vlan_dump(vlan, vlans, sizeof(vlans)));
		eprintf(DEBUG_BRIDGE, "port: ifidx: %d name: %s type:%d vlans: %s%s", ifidx, ifname, type, vlans, (trunc ? "...":""));
	}

	struct nl_addr *addr;
	addr = rtnl_link_get_addr(link);
	if (nl_addr_get_len(addr) != ETH_ALEN)
		goto out;
	int ptp = is_ptp(ifname);
	const char *mac = nl_addr_get_binary_addr(addr);

	port_add(type, ifidx, ifname, ptp, vlan, mac);
out:
	vlan_free(vlan);
}

static void
obj_input_dellink(struct rtnl_link *link, struct nl_msg *msg)
{
	const int ifidx = rtnl_link_get_ifindex(link);
	if (ifidx == bridgeIfIdx) {
		eprintf(DEBUG_ERROR, "my bridge %s removed", rtnl_link_get_name(link));
		exit(254);
	}
	port_del(ifidx);
}

static void
obj_input_route(struct nl_object *obj, void *arg)
{
	struct nf_obj_cb *ctx = arg;
	struct nl_msg *msg = ctx->msg;
	if (isdebug(DEBUG_BRIDGE)) {
		char buf[4096];
		nl_object_dump_buf(obj, buf, sizeof(buf));
		eprintf(DEBUG_BRIDGE,  "received fromDump=%d %s", ctx->fromDump, buf);
	}

	int type = nl_object_get_msgtype(obj);
	switch (type) {
	case RTM_NEWLINK:
		obj_input_newlink((struct rtnl_link *) obj, msg, ctx->fromDump);
		break;
	case RTM_DELLINK:
		obj_input_dellink((struct rtnl_link *) obj, msg);
		break;
	}
}

static int
event_input_route(struct nl_msg *msg, void *arg)
{
	if (isdebug(DEBUG_BRIDGE)) {
		char buf[256] = {0};
		FILE *ofd;

		ofd = fmemopen(buf, sizeof(buf), "w");
		if (ofd && dumpNetlink) {
			nl_msg_dump(msg, ofd);
			eprintf(DEBUG_BRIDGE,  "received message: %s", buf);
			nl_msg_dump(msg, stderr);
		} else {
			eprintf(DEBUG_BRIDGE,  "received message");
		}
		if (ofd)
			fclose(ofd);
	}

	struct nf_obj_cb ctx;
	ctx.msg = msg;
	ctx.fromDump = (arg == nf_sock_dump);

        if (nl_msg_parse(msg, &obj_input_route, &ctx) < 0)
		eprintf(DEBUG_BRIDGE,  "<<EVENT:Route>> Unknown message type");
	return NL_OK;
}

static void
bridge_receive(int s, void* ctx)
{
	struct nl_sock *nf_sock_route = (struct nl_sock *) ctx;
	int ret;
	ret = nl_recvmsgs_default(nf_sock_route);
	if (ret < 0) {
		eprintf(DEBUG_ERROR,  "receiving ROUTE->NEIGH failed on %d error %s", s, strerror(errno));
	}
}

static void
array_append(struct my_array *arr, char* ifname)
{
	char** tmp = realloc(arr->item, (arr->num+1) * sizeof(*arr->item));
	if (!tmp) {
		eprintf(DEBUG_ERROR, "%s:%d %s error parsing command line", __FILE__, __LINE__, __PRETTY_FUNCTION__);
		exit(1);
	}

	tmp[arr->num] = calloc(strlen(ifname)+1, sizeof(char));
	if (!tmp[arr->num]) {
		eprintf(DEBUG_ERROR, "%s:%d %s error parsing command line", __FILE__, __LINE__, __PRETTY_FUNCTION__);
		exit(1);
	}
	strcpy(tmp[arr->num], ifname);
	arr->item = tmp;
	arr->num++;
}

static void
add_if(int c, void *if_pattern)
{

	if (!optarg)
		return;

	eprintf(DEBUG_BRIDGE, "add if prefix %s\n", optarg);
	array_append(if_pattern, optarg);
}

static void
set_if(int c, void *arg)
{
	char **ifname = arg;

	if (!optarg)
		return;

	eprintf(DEBUG_BRIDGE, "set if %s\n", optarg);
	if (*ifname) {
		free(*ifname);
		*ifname = NULL;
	}
	*ifname = calloc(strlen(optarg)+1, sizeof(char));
	if (!*ifname) {
		eprintf(DEBUG_ERROR, "%s:%d %s error parsing command line", __FILE__, __LINE__, __PRETTY_FUNCTION__);
		exit(1);
	}
	strcpy(*ifname, optarg);
}

static void
bridge_start_listen()
{
	assert(nf_sock_bcast == NULL);
	nf_sock_bcast = nl_socket_alloc();
	if (!nf_sock_bcast) {
		eprintf(DEBUG_ERROR, "cannot alloc socket (I): %s", strerror(errno));
		exit(254);
	}
	nl_socket_disable_seq_check(nf_sock_bcast);
	nl_socket_modify_cb(nf_sock_bcast, NL_CB_VALID, NL_CB_CUSTOM, event_input_route, nf_sock_bcast);

	if (nl_connect(nf_sock_bcast, NETLINK_ROUTE) < 0) {
		eprintf(DEBUG_ERROR, "cannot connect I: %s", strerror(errno));
		exit(254);
	}

        if (nl_socket_add_membership(nf_sock_bcast, RTNLGRP_LINK)) {
		eprintf(DEBUG_ERROR, "cannot bind to GRPLINK: %s", strerror(errno));
		exit(254);
	}

	int rffd = nl_socket_get_fd(nf_sock_bcast);
	cb_add_handle(rffd, nf_sock_bcast, bridge_receive);
}

static void
bridge_dump_init()
{
	assert(bridgeIfIdx);

	assert(nf_sock_dump == NULL);
	nf_sock_dump = nl_socket_alloc();
	if (!nf_sock_dump) {
		eprintf(DEBUG_ERROR, "cannot alloc socket (II): %s", strerror(errno));
		exit(254);
	}

	nl_socket_disable_seq_check(nf_sock_dump);
	nl_socket_modify_cb(nf_sock_dump, NL_CB_VALID, NL_CB_CUSTOM, event_input_route, nf_sock_dump);
	nl_socket_disable_auto_ack(nf_sock_dump);

	if (nl_connect(nf_sock_dump, NETLINK_ROUTE) < 0) {
		eprintf(DEBUG_ERROR, "cannot connect II: %s", strerror(errno));
		exit(254);
	}

	int rffd = nl_socket_get_fd(nf_sock_dump);
	cb_add_handle(rffd, nf_sock_dump, bridge_receive);
}

static void
bridge_vlan_init()
{
	assert(nf_sock_vlan == NULL);
	nf_sock_vlan = nl_socket_alloc();
	if (!nf_sock_vlan) {
		eprintf(DEBUG_ERROR, "cannot alloc socket (III): %s", strerror(errno));
		exit(254);
	}

	if (nl_connect(nf_sock_vlan, NETLINK_ROUTE) < 0) {
		eprintf(DEBUG_ERROR, "cannot connect III: %s", strerror(errno));
		exit(254);
	}
}

static void
bridge_dump_links()
{
	/* nl_rtgen_request(nf_sock_dump, RTM_GETNEIGH, AF_BRIDGE, NLM_F_DUMP)
	 * produces an undersized payload and thus gets discarded by the kernel.
	 */
	/*
	 * getting vlan information is only supported for AF_BRIDGE w NLM_F_DUMP RTM_GETLINK requests.
	 * All others do not have it.
	 * Sadly, AF_BRIGE+NLM_F_DUMP->kernel:rtnl_bridge_getlink does not allow to filter for master device or ifidx.
	 */
	struct ifinfomsg msg = { 0 };
	struct nl_msg *nlmsg = NULL;

	msg.ifi_family = AF_BRIDGE;
	//msg.ifi_index = ifidx;	

	nlmsg = nlmsg_alloc_simple(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP);
	//nlmsg = nlmsg_alloc_simple(RTM_GETLINK, NLM_F_REQUEST | (ifidx ? 0 : NLM_F_DUMP));
	if (!nlmsg) {
		eprintf(DEBUG_ERROR, "out of memory");
		exit(254);
	}
	if (nlmsg_append(nlmsg, &msg, sizeof(msg), NLMSG_ALIGNTO) < 0) {
		eprintf(DEBUG_ERROR, "out of memory");
		exit(254);
	}
	/*
	if (!ifidx &&
	    nla_put_u32(nlmsg, IFLA_MASTER, bridgeIfIdx) < 0) {
		eprintf(DEBUG_ERROR, "out of memory");
		exit(254);
	}
	*/
	if (nla_put_u32(nlmsg, IFLA_EXT_MASK, RTEXT_FILTER_BRVLAN) < 0) {
		eprintf(DEBUG_ERROR, "out of memory");
		exit(254);
	}

	if (isdebug(DEBUG_BRIDGE)) {
		char buf[1024] = {0};
		FILE *ofd;

		ofd = fmemopen(buf, sizeof(buf), "w");
		if (ofd && dumpNetlink) {
			nl_msg_dump(nlmsg, ofd);
			eprintf(DEBUG_BRIDGE,  "send message: %s", buf);
			//nl_msg_dump(nlmsg, stderr);
		} else {
			eprintf(DEBUG_BRIDGE,  "send message");
		}
		if (ofd)
			fclose(ofd);
	}

	if (nl_send_auto(nf_sock_dump, nlmsg) < 0) { /* ACK was disabled above */
		eprintf(DEBUG_ERROR, "netlink error");
		exit(254);
	}

	nlmsg_free(nlmsg);
}

static void
bridge_start(void *ctx)
{
	eprintf(DEBUG_BRIDGE,  "Listen to ROUTE->LINK notifications");

	if (!bridge) {
		eprintf(DEBUG_ERROR, "no bridge set");
		exit(254);
	}

	bridgeIfIdx = if_nametoindex(bridge);

	if (!bridgeIfIdx) {
		eprintf(DEBUG_ERROR, "bridge does not exist");
		exit(254);
	}

	/* connect to netlink route to get notified of new bridge ports */
	bridge_start_listen();

	/* connect to netlink route to dump all known bridge ports */
	bridge_dump_init();
	//bridge_dump_links(bridgeIfIdx);
	bridge_dump_links();

	/* socket or vlan_add or vlan_del */
	bridge_vlan_init();
}

static void
setDumpNetlink(int c, void *arg)
{
	dumpNetlink = 1;
}

static __attribute__((constructor)) void
bridge_init()
{
	{
		struct option long_option = {"epif", required_argument, 0, 0};
		add_option_cb(long_option, add_if, &epIfPattern);
	}
	{
		struct option long_option = {"uplinkif", required_argument, 0, 0};
		add_option_cb(long_option, add_if, &uplinkIfPattern);
	}
	{
		struct option long_option = {"ptpif", required_argument, 0, 0};
		add_option_cb(long_option, add_if, &ptpIfPattern);
	}
	{
		struct option long_option = {"bridge", required_argument, 0, 0};
		add_option_cb(long_option, set_if, &bridge);
	}
	{
		struct option long_option = {"bridge-dump-netlink", no_argument, 0, 0};
		add_option_cb(long_option, setDumpNetlink, NULL);
	}
	cb_add_timer(0, 0, NULL, bridge_start);
}

