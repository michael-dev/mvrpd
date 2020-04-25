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

#ifndef MVRPD_PORT
#define MVRPD_PORT

#include <net/if.h>
#include <netinet/ether.h>
#include <time.h>

struct vlan_arr;

enum {
	IF_UNDEF  = 0,
	IF_MVRP = 1,
	IF_STATIC   = 2
};

struct if_entry
{
	int type;
	int ifidx;
	char ifname[IFNAMSIZ];
	char mac[ETH_ALEN];
	int ptp;

	/* vlans configured locally, managed by bridge NEWLINK monitoring; mainly for IF_STATIC */
	struct vlan_arr *vlan_state;

	/* vlans declared (aka requested) locally on IF_MVRP interfaces */
	struct vlan_arr *vlan_declared_local;
	struct vlan_arr *vlan_declared_local_lastSend;

	/* vlans declared (aka requested) remotely on IF_MVRP interfaces */
	struct vlan_arr *vlan_declared_remote;
	/* leave: wait for others on link to say "but hey, I still need it" */
	struct vlan_arr *vlan_declared_remote_leave;
	struct vlan_arr *vlan_declared_remote_leave2;
	/* leaveAll needs a bigger timer as we see too much packet loss so periodic timer can make up */
	struct vlan_arr *vlan_declared_remote_leaveAll;
	struct vlan_arr *vlan_declared_remote_leaveAll2;

	/* vlans configured locally managed by mvrpd on IF_MVRP interfaces */
	struct vlan_arr *vlan_registered_local;
	struct vlan_arr *vlan_registered_local_lastSend;

	/* vlan registered (aka configured) remotely on IF_MVRP interfaces */
	struct vlan_arr *vlan_registered_remote;

	/* MVRP state tracking */
	unsigned int needSend:1; // indicates a leave message has been received and thus join should be sent
	time_t lastLeaveAll; /* sent or received leaveAll at this timestamp */
	time_t lastLeaveAllFromMe; /* was it sent or receive at lastLeaveAll? */
	time_t lastLeaveAllLeaveTimer; /* when did i last purge vlans not refreshed after leaveAll */
	time_t lastLeaveTimer; /* leave, not leaveAll */
	time_t lastSent; /* periodic timer */

	/* debugging */
	struct vlan_arr *vlan_to_add_last_print;
	struct vlan_arr *vlan_registered_local_last_print;
	struct vlan_arr *vlan_declared_local_last_print;

	/* else */
	struct ether_socket *sock;
	struct if_entry *next;
};


void port_add(int type, int ifidx, const char *ifname, int ptp, struct vlan_arr *vlan, const char *mac);
void port_del(int ifidx);
void port_vlan_changed();
struct if_entry *port_get_by_ifidx(int ifidx);
void for_each_port(void (*cb) (struct if_entry *port, void *ctx), void *ctx);

#endif
