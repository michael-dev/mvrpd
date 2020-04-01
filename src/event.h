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
#ifndef MVRPD_EVENT
#define MVRPD_EVENT

#include <stdint.h>

typedef void (*packet_cb) (const int ptype, const uint8_t *packet, const int len, const char* ifname, const int ifindex);
typedef void (*handle_cb) (int h, void* ctx);
typedef void (*signal_cb) (int h);

void cb_add_packet_cb(packet_cb cb);
void cb_call_packet_cb(const int ptype, const uint8_t *packet, const int len, const char* ifname, const int ifindex);
void cb_add_handle(int h, void* ctx, handle_cb cb);
void cb_del_handle(int h, void* ctx, handle_cb cb);
void cb_add_signal(int s, signal_cb cb);

void event_runloop();

#endif

