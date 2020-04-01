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

#ifndef MVRPD_VLAN
#define MVRPD_VLAN

#include <stdint.h>
#include <stddef.h>

struct vlan_arr;

int vlan_set(struct vlan_arr *arr, uint16_t vid); // returns old mask
int vlan_unset(struct vlan_arr *arr, uint16_t vid); // returns old mask
int vlan_test(struct vlan_arr *arr, uint16_t vid);
struct vlan_arr *vlan_alloc(const char *name);
struct vlan_arr *vlan_clone(struct vlan_arr *arr, const char *name);
void vlan_free(struct vlan_arr *arr);
int vlan_next(struct vlan_arr *arr, int *iterator, uint16_t *vid); // 1 on end, 0 if found
size_t vlan_dump(struct vlan_arr *arr, char *buf, size_t buflen);

#endif
