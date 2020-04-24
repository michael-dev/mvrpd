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

struct if_entry
{
	int type;
	int ifidx;
	char ifname[IFNAMSIZ];
	char mac[ETH_ALEN];
	int ptp;

	/* vlans configured locally, managed by bridge NEWLINK monitoring */
	struct vlan_arr *vlan_registered;
	struct vlan_arr *vlan_registered_lastSend;

	/* vlans configured locally managed by mvrpd */
	struct vlan_arr *vlan_state;

	/* vlans declared (aka requested) remotely, managed by mvrp */
	struct vlan_arr *vlan_declared_remote;
	struct vlan_arr *vlan_declared_remote_leave;
	struct vlan_arr *vlan_declared_remote_leave2;

	unsigned int needSend:1; // indicates a leave message has been received and thus join should be sent
	time_t lastLeaveAll;
	time_t lastLeaveAllFromMe;
	time_t lastLeaveTimer;
	time_t lastSent;

	/* vlans declared (aka requested) locally, managed by all other ports (uplink or not) */
	struct vlan_arr *vlan_declared_local;
	struct vlan_arr *vlan_declared_local_lastSend;

	/* debugging */
	struct vlan_arr *vlan_to_add_last_print;
	struct vlan_arr *vlan_state_last_print;
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
