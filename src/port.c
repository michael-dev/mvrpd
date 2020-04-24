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
#include "port.h"
#include "signal.h"
#include "debug.h"
#include "event.h"
#include "timer.h"
#include "mvrp.h"
#include "vlan.h"
#include "bridge.h"
#include "cmdline.h"

#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>

#include <net/if.h>
#include <netinet/ether.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


static struct if_entry* ifHead = NULL;
static struct vlan_arr *ignVlan = NULL;
static unsigned char restrictToEp = 0;

void
for_each_port(void (*cb) (struct if_entry *port, void *ctx), void *ctx)
{
	struct if_entry* entry;
	for (entry = ifHead; entry; entry = entry->next) {
		cb(entry, ctx);
	}
}

static struct if_entry *
get_if(const int ifidx, struct if_entry **prev)
{
	struct if_entry* entry;
	if (prev)
		*prev = NULL;
	for (entry = ifHead; entry; entry = entry->next) {
		if (entry->ifidx == ifidx)
			break;
		if (prev)
			*prev = entry;
	}
	return entry;
}

struct if_entry *
port_get_by_ifidx(int ifidx)
{
	return get_if(ifidx, NULL);
}

static struct if_entry *
add_if(const int ifidx)
{
	struct if_entry* entry = malloc(sizeof(*entry));
	if (!entry) {
		eprintf(DEBUG_ERROR, "out of memory at %s:%d in %s", __FILE__, __LINE__, __PRETTY_FUNCTION__);
		return NULL;
	}
	memset(entry, 0, sizeof(*entry));
	entry->ifidx = ifidx;
	entry->next = ifHead;
	entry->vlan_registered = vlan_alloc("port->vr");
	entry->vlan_to_add_last_print = vlan_alloc("port->vtalp");
	entry->vlan_state_last_print = vlan_alloc("port->vslp");

	ifHead = entry;
	return entry;
}

static void
conf_uplink(struct if_entry *entry)
{
	assert(!entry->sock);
	entry->sock = mvrp_listen(entry->ifidx, entry->ifname, entry->mac);
	assert(entry->sock);
	
	assert(!entry->vlan_state);
	entry->vlan_state = vlan_alloc("port->vs");
	assert(entry->vlan_state);

	assert(!entry->vlan_registered_lastSend);
	entry->vlan_registered_lastSend = vlan_alloc("port->vrlS");
	assert(entry->vlan_registered_lastSend);

	assert(!entry->vlan_declared_remote);
	entry->vlan_declared_remote = vlan_alloc("port->vdr");
	assert(entry->vlan_declared_remote);
	
	assert(!entry->vlan_declared_remote_leave);
	entry->vlan_declared_remote_leave = vlan_alloc("port->vdrl");
	assert(entry->vlan_declared_remote_leave);
	
	assert(!entry->vlan_declared_remote_leave2);
	entry->vlan_declared_remote_leave2 = vlan_alloc("port->vdrl2");
	assert(entry->vlan_declared_remote_leave2);

	assert(!entry->vlan_declared_local);
	entry->vlan_declared_local = vlan_alloc("port->vdl");
	assert(entry->vlan_declared_local);

	assert(!entry->vlan_declared_local_lastSend);
	entry->vlan_declared_local_lastSend = vlan_alloc("port->vdllS");
	assert(entry->vlan_declared_local_lastSend);
}

static void
deconf_uplink(struct if_entry *entry)
{
	if (entry->sock)
		mvrp_close(entry->sock);
	entry->sock =  NULL;

	vlan_free(entry->vlan_state);
	entry->vlan_state = NULL;

	vlan_free(entry->vlan_registered_lastSend);
	entry->vlan_registered_lastSend = NULL;

	vlan_free(entry->vlan_declared_remote);
	entry->vlan_declared_remote = NULL;

	vlan_free(entry->vlan_declared_remote_leave);
	entry->vlan_declared_remote_leave = NULL;

	vlan_free(entry->vlan_declared_remote_leave2);
	entry->vlan_declared_remote_leave2 = NULL;

	vlan_free(entry->vlan_declared_local);
	entry->vlan_declared_local = NULL;

	vlan_free(entry->vlan_declared_local_lastSend);
	entry->vlan_declared_local_lastSend = NULL;
}

static void
update_if(struct if_entry *entry, int type, const char *ifname, const char *mac, int ptp, struct vlan_arr *vlan)
{
	if (mac)
		memcpy(entry->mac, mac, ETH_ALEN);
	else
		memset(entry->mac, 0, ETH_ALEN);
	entry->ptp = ptp;
	strncpy(entry->ifname, ifname, IFNAMSIZ-1); 

	vlan_free(entry->vlan_registered);
	entry->vlan_registered = vlan_clone(vlan, "port->vr");
	if (!entry->vlan_registered) {
		eprintf(DEBUG_ERROR, "out of memory at %s:%d in %s", __FILE__, __LINE__, __PRETTY_FUNCTION__);
		exit(254);
	}

	if (isdebug(DEBUG_PORT)) {
		char vlans[4096];
		int trunc = (sizeof(vlans) == vlan_dump(entry->vlan_registered, vlans, sizeof(vlans)));
		eprintf(DEBUG_PORT,  "ifidx: %d name: %s type:%d ptp:%d vlans: %s%s", entry->ifidx, entry->ifname, type,entry->ptp, vlans, (trunc ? "...":""));
	}

	if (entry->type == type)
		return;
	if (entry->type == 1)
		/* uplink aka mvrp */
		deconf_uplink(entry);
	entry->type = type;
	if (entry->type == 1)
		/* uplink aka mvrp */
		conf_uplink(entry);
}

static void
dump_if(int s)
{
	struct if_entry* entry;
	char vlans[4096];

 	for (entry = ifHead; entry; entry = entry->next) {
		int trunc = (sizeof(vlans) == vlan_dump(entry->vlan_registered, vlans, sizeof(vlans)));
		eprintf(DEBUG_PORT,  "port: ifidx: %d name: %s type:%d ptp:%d vlans: %s%s", entry->ifidx, entry->ifname, entry->type, entry->ptp, vlans, (trunc ? "...":""));
	}
}

static void
port_configure_br_vlan(struct if_entry *entry, struct vlan_arr *vlan_register) {
	int it = 0, hasadd = 0, hasdel = 0;
	uint16_t vid = 0;
	struct vlan_arr *vlan_del = vlan_alloc("vlan-del");
	struct vlan_arr *vlan_add = vlan_alloc("vlan-add");

	while (vlan_next(vlan_register, &it, &vid) == 0) {
		if (vlan_test(ignVlan, vid))
			continue;
		if (!vlan_test(entry->vlan_declared_remote, vid))
			continue;
		if (vlan_test(entry->vlan_registered, vid) && 
		    vlan_test(entry->vlan_state, vid))
			continue;
		vlan_set(entry->vlan_state, vid);
		vlan_set(vlan_add, vid);
		hasadd = 1;
	}

	it = 0;
	vid = 0;
	while (vlan_next(entry->vlan_state, &it, &vid) == 0) {
		if (vlan_test(ignVlan, vid))
			continue;
		if (vlan_test(vlan_register, vid) &&
		    vlan_test(entry->vlan_declared_remote, vid))
			continue;
		vlan_unset(entry->vlan_state, vid);
		vlan_set(vlan_del, vid);
		hasdel = 1;
	}
	
	it = 0;
	vid = 0;
	while (vlan_next(entry->vlan_registered, &it, &vid) == 0) {
		if (vlan_test(ignVlan, vid))
			continue;
		if (vlan_test(vlan_register, vid) &&
		    vlan_test(entry->vlan_declared_remote, vid))
			continue;
		vlan_unset(entry->vlan_state, vid); // vlan_registered is managed by NEWLINK messages on bridge!
		vlan_set(vlan_del, vid);
		hasdel = 1;
	}

	if (isdebug(DEBUG_PORT | DEBUG_VERBOSE) && hasdel) {
		char buf[4096];
		int trunc = (sizeof(buf) == vlan_dump(vlan_del, buf, sizeof(buf)));
		eprintf(DEBUG_PORT | DEBUG_VERBOSE, "del vlans from port %s: %s%s", entry->ifname, buf, (trunc ? "..." : ""));
	}
	if (isdebug(DEBUG_PORT | DEBUG_VERBOSE) && hasadd) {
		char buf[4096];
		int trunc = (sizeof(buf) == vlan_dump(vlan_add, buf, sizeof(buf)));
		eprintf(DEBUG_PORT | DEBUG_VERBOSE, "add vlans to port %s: %s%s", entry->ifname, buf, (trunc ? "..." : ""));
	}
	if (isdebug(DEBUG_PORT)) {
		char buf[4096];
		int trunc;
		eprintf(DEBUG_PORT, "configure vlans on %s", entry->ifname);
		trunc = (sizeof(buf) == vlan_dump(vlan_add, buf, sizeof(buf)));
		eprintf(DEBUG_PORT, " * add vlan %s%s, hasadd=%d", buf, trunc ? "..." : "", hasadd);
		trunc = (sizeof(buf) == vlan_dump(vlan_del, buf, sizeof(buf)));
		eprintf(DEBUG_PORT, " * del vlan %s%s, hasdel=%d", buf, trunc ? "..." : "", hasdel);
		trunc = (sizeof(buf) == vlan_dump(entry->vlan_declared_remote, buf, sizeof(buf)));
		eprintf(DEBUG_PORT, " * declared_remote: %s%s", buf, trunc ? "..." : "");
		trunc = (sizeof(buf) == vlan_dump(vlan_register, buf, sizeof(buf)));
		eprintf(DEBUG_PORT, " * register locally: %s%s", buf, trunc ? "..." : "");
		trunc = (sizeof(buf) == vlan_dump(entry->vlan_registered, buf, sizeof(buf)));
		eprintf(DEBUG_PORT, " * registered locally: %s%s", buf, trunc ? "..." : "");
		trunc = (sizeof(buf) == vlan_dump(entry->vlan_state, buf, sizeof(buf)));
		eprintf(DEBUG_PORT, " * state: %s%s", buf, trunc ? "..." : "");
		trunc = (sizeof(buf) == vlan_dump(ignVlan, buf, sizeof(buf)));
		eprintf(DEBUG_PORT, " * ignore: %s%s", buf, trunc ? "..." : "");
	}
	if (hasdel)
		br_vlan_del(entry->ifidx, vlan_del);
	if (hasadd)
		br_vlan_add(entry->ifidx, vlan_add);

	vlan_free(vlan_add);
	vlan_free(vlan_del);
}

static void
port_recompute_timer(void *ctx)
{
	struct if_entry* entry;
	// a vid is in both vlan_wanted* arrays iff at least two ports request it
	// if one port requests it, it is set in vlan_wanted0 
	struct vlan_arr *vlan_wanted0 = vlan_alloc("vlan_wanted0");
	struct vlan_arr *vlan_wanted1 = vlan_alloc("vlan_wanted1");

	for (entry = ifHead; entry; entry = entry->next) {
		struct vlan_arr *vlan_to_add;
		if (entry->type == 1 && !restrictToEp)
			// uplink
			vlan_to_add = entry->vlan_declared_remote;
		else if (entry->type == 2)
			// ep
			vlan_to_add = entry->vlan_registered;
		else
			continue;

		if (isdebug(DEBUG_PORT) && vlan_to_add) {
			char vlans[4096];
			int trunc = (sizeof(vlans) == vlan_dump(vlan_to_add, vlans, sizeof(vlans)));
			eprintf(DEBUG_PORT,  "ifidx: %d name: %s type:%d ptp:%d vlans-to-add: %s%s", entry->ifidx, entry->ifname, entry->type,entry->ptp, vlans, (trunc ? "...":""));
		}
		if (isdebug(DEBUG_VERBOSE) &&
		    vlan_compare(entry->vlan_to_add_last_print, vlan_to_add)) {
			char vlans[4096];
			int trunc = (sizeof(vlans) == vlan_dump(vlan_to_add, vlans, sizeof(vlans)));
			eprintf(DEBUG_VERBOSE,  "ifidx: %d name: %s type:%d ptp:%d vlans-to-add: %s%s", entry->ifidx, entry->ifname, entry->type,entry->ptp, vlans, (trunc ? "...":""));
			vlan_free(entry->vlan_to_add_last_print);
			entry->vlan_to_add_last_print = vlan_clone(vlan_to_add,"port->vtalp");
		}

		int it = 0;
		uint16_t vid = 0;
		while (vlan_next(vlan_to_add, &it, &vid) == 0) {
			if (vlan_test(ignVlan, vid))
				continue;
			if (restrictToEp ||
			    vlan_set(vlan_wanted0, vid))
				vlan_set(vlan_wanted1, vid);
		}
	}

	if (isdebug(DEBUG_PORT)) {
		char vlans[4096];
		int trunc;
		trunc = (sizeof(vlans) == vlan_dump(vlan_wanted0, vlans, sizeof(vlans)));
		eprintf(DEBUG_PORT,  "wanted0: %s%s", vlans, (trunc ? "...":""));
		trunc = (sizeof(vlans) == vlan_dump(vlan_wanted1, vlans, sizeof(vlans)));
		eprintf(DEBUG_PORT,  "wanted1: %s%s", vlans, (trunc ? "...":""));
	}

	for (entry = ifHead; entry; entry = entry->next) {
		if (entry->type != 1)
			continue;

		if (isdebug(DEBUG_VERBOSE) && restrictToEp &&
		    vlan_compare(entry->vlan_to_add_last_print, entry->vlan_declared_remote)) {
			char vlans[4096];
			int trunc = (sizeof(vlans) == vlan_dump(entry->vlan_declared_remote, vlans, sizeof(vlans)));
			eprintf(DEBUG_VERBOSE,  "ifidx: %d name: %s type:%d ptp:%d vlans declared remote: %s%s", entry->ifidx, entry->ifname, entry->type,entry->ptp, vlans, (trunc ? "...":""));
			vlan_free(entry->vlan_to_add_last_print);
			entry->vlan_to_add_last_print = vlan_clone(entry->vlan_declared_remote,"port->vtalp");
		}

		vlan_free(entry->vlan_declared_local);
		entry->vlan_declared_local = vlan_clone(vlan_wanted1, "port->vdl");
		// declare locally: every vid on at least one other port
		// that is at least two ports OR at least one port but not this
		// iff restrictToEp -> wanted0 is empty
		int it = 0;
		uint16_t vid = 0;
		while (vlan_next(vlan_wanted0, &it, &vid) == 0) {
			if (vlan_test(entry->vlan_declared_remote, vid))
				continue;
			vlan_set(entry->vlan_declared_local, vid);
		}

		port_configure_br_vlan(entry, vlan_wanted1);
		mvrp_send(entry);

		if (isdebug(DEBUG_VERBOSE) &&
		    vlan_compare(entry->vlan_state_last_print, entry->vlan_state)) {
			char vlans[4096];
			int trunc = (sizeof(vlans) == vlan_dump(entry->vlan_state, vlans, sizeof(vlans)));
			eprintf(DEBUG_VERBOSE,  "ifidx: %d name: %s type:%d ptp:%d vlans-state: %s%s", entry->ifidx, entry->ifname, entry->type,entry->ptp, vlans, (trunc ? "...":""));
			vlan_free(entry->vlan_state_last_print);
			entry->vlan_state_last_print = vlan_clone(entry->vlan_state,"port->vslp");
		}
	}

	vlan_free(vlan_wanted0);
	vlan_free(vlan_wanted1);
}

void port_vlan_changed()
{
	cb_del_timer(NULL, port_recompute_timer);
	cb_add_timer(0, 0, NULL, port_recompute_timer);
}

void port_del(int ifidx)
{
	struct if_entry *prev;
	struct if_entry *entry = get_if(ifidx, &prev);
	if (!entry)
		return;
	if (prev)
		prev->next = entry->next;
	else
		ifHead = entry->next;

	if (entry->type == 1)
		/* uplink aka mvrp */
		deconf_uplink(entry);

	vlan_free(entry->vlan_to_add_last_print);
	vlan_free(entry->vlan_state_last_print);

	vlan_free(entry->vlan_registered);
	free(entry);
}

void port_add(int type, int ifidx, const char *ifname, int ptp, struct vlan_arr *vlan, const char *mac)
{
	struct if_entry *entry = get_if(ifidx, NULL);
	if (!entry)
		entry = add_if(ifidx);
	update_if(entry, type, ifname, mac, ptp, vlan);
	port_vlan_changed();
}

static void
addIgnVLAN(int c, void *arg)
{
	if (!optarg)
		return;
	int vid = atoi(optarg);
	if (vid <= 0 || vid >= 4095)
	{
		eprintf(DEBUG_ERROR, "invalid vlan id given: %d", vid);
		exit(254);
	}
	vlan_set(ignVlan, vid);
}

static void
setRestrictToEp(int c, void *arg)
{
	restrictToEp = 1;
}

static __attribute__((constructor)) void port_init()
{
	ignVlan = vlan_alloc(NULL);
	cb_add_signal(SIGUSR1, dump_if);
	{
		struct option long_option = {"ignore-vlan", required_argument, 0, 0};
		add_option_cb(long_option, addIgnVLAN, NULL);
	}
	{
		struct option long_option = {"restrict-to-ep", no_argument, 0, 0};
		add_option_cb(long_option, setRestrictToEp, NULL);
	}
}

