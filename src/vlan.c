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

#include "vlan.h"
#include "debug.h"

#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

#define MIN(a,b) ((a < b) ? a : b)
#define MAX(a,b) ((a > b) ? a : b)

struct vlan_entry {
	uint8_t start; // vid / 16
	uint8_t offset; // offset in data array
} __attribute__((packed));

struct vlan_arr {
	uint16_t numentries;
	char name[32];

	uint8_t nummeta;
	/* sorted by start, implies ordering of offset
	 * for successive entries: delta in start * 16 is minimum distance in offset
	 */
	struct vlan_entry *meta;

	uint8_t numbitmap;
	uint16_t *bitmap;

	uint8_t lastidx; // offset in meta array
} __attribute__((packed));

static inline uint8_t
vlan_offset(struct vlan_arr *arr, uint16_t metaidx)
{
	return (metaidx < arr->nummeta) ? arr->meta[metaidx].offset : arr->numbitmap;
}

static inline uint16_t
vlan_start_vid(struct vlan_arr *arr, uint16_t metaidx)
{
	return (metaidx < arr->nummeta) ? arr->meta[metaidx].start * 16 : 4096;
}

static inline uint16_t
vlan_end_vid(struct vlan_arr *arr, uint16_t metaidx) // first not included in metaidx
{
	return (vlan_offset(arr, metaidx + 1) - vlan_offset(arr, metaidx)) * 16 + vlan_start_vid(arr, metaidx);
}

/* returns 1 if found, else 0; *metaidx is set to match or its successor */
static int
vlan_find(struct vlan_arr *arr, uint16_t vid, uint16_t *metaidx)
{
	uint16_t right = 0;
	uint16_t left = arr->nummeta;

	/* exploit the fact that most requests target close-by consecutive vids
	 * even if this is not a perfect match, still reduce the lookup range */
	for (uint16_t middle = (arr->lastidx > 0) ? arr->lastidx - 1 : 0;
	     middle < MIN(arr->nummeta, arr->lastidx + 2);
	     middle++) {
		if (vid >= vlan_start_vid(arr, middle)) {
			right = MAX(middle, right);
		} else {
			left = MIN(middle, left);
		}
		if (vid >= vlan_end_vid(arr, middle)) {
			right = MAX(middle + 1, right);
		} else {
			left = MIN(middle + 1, left);
		}
	}

	while (right < left) {
		uint16_t middle = (left + right) / 2;
		assert(middle < arr->nummeta);

		if (vid < vlan_start_vid(arr, middle)) {
			left = middle; // vid needs to come before middle
			continue;
		}

		assert(vlan_start_vid(arr, middle + 1) >= vlan_end_vid(arr, middle));

		if (vid >= vlan_end_vid(arr, middle)) {
			// vid needs come after middle
			right = middle + 1;
			continue;
		}

		if (!(vid >= vlan_start_vid(arr, middle)) || !(vid < vlan_end_vid(arr, middle))) {
			eprintf(DEBUG_ERROR, "middle=%hu vid=%hu, start_vid=%hu end_vid=%hu", middle, vid, vlan_start_vid(arr, middle), vlan_end_vid(arr, middle));
		}

		assert(vid >= vlan_start_vid(arr, middle));
		assert(vid < vlan_end_vid(arr, middle));

		*metaidx = middle;
		arr->lastidx = middle;

		return 1;
	}

	assert(right == left);
	*metaidx = right; // successor idx
	arr->lastidx = right;

	return 0;
}

static uint16_t
vlan_find_or_add_room(struct vlan_arr *arr, uint16_t vid)
{
	uint16_t succ;

	if (vlan_find(arr, vid, &succ) == 1)
		return succ;

	unsigned char merge = 0; // 1 for prev, 2 for succ
	uint8_t extrabitmap = 0;

	assert(vid < vlan_start_vid(arr, succ));
	assert(succ == 0 || vid >= vlan_end_vid(arr, succ-1));

	if (succ > 0 &&
	    vlan_end_vid(arr, succ-1) / 16 == vid / 16 - 1)
		extrabitmap += 1;
	if (succ > 0 &&
	    vlan_end_vid(arr, succ-1) / 16 >= vid / 16 - 1) {
		merge += 1;
		extrabitmap += 1;
	}
	if (vlan_start_vid(arr, succ) / 16 <= vid / 16 + 2) {
		merge += 2;
		extrabitmap += 1;
	}
	if (vlan_start_vid(arr, succ) / 16 == vid / 16 + 2)
		extrabitmap += 1;

	if (merge == 0)
		extrabitmap = 1; /* plus an extra metaidx entry */
	if (merge == 3)
		extrabitmap -= 1; /* the bitmap byte for vid/16 was counted twice */

	eprintf(DEBUG_GENERAL, "arr %s(%p) nummeta=%hu metabitmap=%hu vid=%hu, idx=%hu vlan_offset=%hu vlan_start_vid=%hu vlan_end_vid=%hu, extrabitmap=%hu merge=%d",
		arr->name, arr, arr->nummeta, arr->numbitmap, vid, succ, vlan_offset(arr, succ), vlan_start_vid(arr, succ), vlan_end_vid(arr, succ), extrabitmap, merge);

	uint8_t startoffset = vlan_offset(arr, succ); // fetch before numbitmap is updated
	eprintf(DEBUG_GENERAL, "old: arr->bitmap=%p startoffset=%d e=%d numbitmap=%d", arr->bitmap, startoffset, extrabitmap, (int) arr->numbitmap);
	assert(extrabitmap);
	assert(arr->numbitmap <= UCHAR_MAX - extrabitmap);
	assert(startoffset <= arr->numbitmap);

	arr->bitmap = realloc(arr->bitmap, (arr->numbitmap + extrabitmap) * sizeof(*arr->bitmap));
	arr->numbitmap += extrabitmap;
	assert(arr->bitmap);

	for (uint8_t i = succ; i < arr->nummeta; i++) {
		assert(arr->meta[i].offset >= startoffset);
		arr->meta[i].offset += extrabitmap;
	}
	for (uint8_t i = arr->numbitmap - 1; i >= startoffset + extrabitmap; i--) {
//		eprintf(DEBUG_GENERAL, "arr->bitmap=%p i=%d i-e=%d numbitmap=%d", arr->bitmap, i, i-extrabitmap, (int) arr->numbitmap);
		arr->bitmap[i] = arr->bitmap[i - extrabitmap];
	}
	for (uint8_t i = startoffset; i < ((uint8_t) (startoffset + extrabitmap)); i++) {
//		eprintf(DEBUG_GENERAL, "arr->bitmap=%p i=%d startoffset=%d e=%d numbitmap=%d", arr->bitmap, i, startoffset, extrabitmap, (int) arr->numbitmap);
		arr->bitmap[i] = 0;
	}

	switch (merge) {
	case 3: // merge prev and succ
		eprintf(DEBUG_GENERAL, "end_vid=%hu start_vid=%hu succ=%hu", vlan_end_vid(arr, succ-1), vlan_start_vid(arr, succ), succ);
		assert(vlan_end_vid(arr, succ - 1) == vlan_start_vid(arr, succ));
		// drop succ from meta list
		for (uint16_t i = succ; i < arr->nummeta - 1; i++)
			arr->meta[i] = arr->meta[i+1];
		arr->nummeta--;
		arr->meta = realloc(arr->meta, arr->nummeta * sizeof(*arr->meta));
		assert(arr->meta);
		return succ - 1;
	case 2: // merge succ but not prev
		assert(vid >= vlan_start_vid(arr, succ) - extrabitmap * 16);
		arr->meta[succ].offset -= extrabitmap;
		arr->meta[succ].start -= extrabitmap;
		return succ;
	case 1: // merge prev but not succ
		assert(vid < vlan_end_vid(arr, succ - 1));
		return succ - 1;
	case 0: // merge none
		// insert into meta list
		arr->nummeta++;
		arr->meta = realloc(arr->meta, arr->nummeta * sizeof(*arr->meta));
		assert(arr->meta);
		for (uint16_t i = succ; i < arr->nummeta - 1; i++)
			arr->meta[i+1] = arr->meta[i];
		arr->meta[succ].offset = startoffset;
		arr->meta[succ].start = vid / 16;
		return succ;
	}

	assert(0);
	return 0;
}

int
vlan_set(struct vlan_arr *arr, uint16_t vid)
{
	eprintf(DEBUG_GENERAL, "%s(%p) set %hu", arr->name, arr, vid);

	uint16_t metaidx = vlan_find_or_add_room(arr, vid);
	assert(vid >= vlan_start_vid(arr, metaidx));
	assert(vid < vlan_end_vid(arr, metaidx));

	uint16_t offset = vlan_offset(arr, metaidx) + (vid - vlan_start_vid(arr, metaidx)) / 16;
	assert(offset < arr->numbitmap);

	uint16_t mask = 1 << (vid % 16);
	int wasset = !!( arr->bitmap[offset] & mask);
	arr->bitmap[offset] |= mask;

	if (!wasset)
		arr->numentries++;

	return wasset;
}

static void
vlan_rebuild(struct vlan_arr *arr)
{
	struct vlan_arr *n = vlan_alloc(NULL);
	assert(n);

	int it = 0;
	uint16_t vid = 0;
	while (vlan_next(arr, &it, &vid) == 0) {
		vlan_set(n, vid);
	}

	free(arr->meta);
	arr->meta = n->meta;
	n->meta = NULL;

	free(arr->bitmap);
	arr->bitmap = n->bitmap;
	n->bitmap = NULL;

	arr->nummeta = n->nummeta;
	n->nummeta = 0;

	arr->numbitmap = n->numbitmap;
	n->numbitmap = 0;

	assert(arr->numentries == n->numentries);

	vlan_free(n);
}

int
vlan_unset(struct vlan_arr *arr, uint16_t vid)
{
	eprintf(DEBUG_GENERAL, "%s(%p) unset %hu", arr->name, arr, vid);
	uint16_t metaidx;

	if (vlan_find(arr, vid, &metaidx) == 0)
		return 0;

	assert(vid >= vlan_start_vid(arr, metaidx));
	assert(vid < vlan_end_vid(arr, metaidx));

	uint16_t offset = vlan_offset(arr, metaidx) + (vid - vlan_start_vid(arr, metaidx)) / 16;
	assert(offset < arr->numbitmap);

	uint16_t mask = 1 << (vid % 16);
	int wasset = !!( arr->bitmap[offset] & mask);
	arr->bitmap[offset] &= ~mask;

	if (wasset)
		arr->numentries--;

	if (arr->numbitmap > arr->numentries)
		vlan_rebuild(arr);

	return wasset;
}

int
vlan_test(struct vlan_arr *arr, uint16_t vid)
{
	eprintf(DEBUG_GENERAL, "%s(%p) test %hu", arr->name, arr, vid);
	uint16_t metaidx;

	if (vlan_find(arr, vid, &metaidx) == 0)
		return 0;

	assert(vid >= vlan_start_vid(arr, metaidx));
	assert(vid < vlan_end_vid(arr, metaidx));

	uint16_t offset = vlan_offset(arr, metaidx) + (vid - vlan_start_vid(arr, metaidx)) / 16;
	assert(offset < arr->numbitmap);

	uint16_t mask = 1 << (vid % 16);
	int wasset = !!( arr->bitmap[offset] & mask);

	return wasset;
}

// 1 on end, 0 if found
int
vlan_next(struct vlan_arr *arr, int *iterator, uint16_t *vid)
{
	if (!*vid)
		*iterator = 0;
	(*vid)++;

	while (*iterator < arr->nummeta) {
		if (*vid >= vlan_end_vid(arr, *iterator)) {
			(*iterator)++;
			continue;
		}

		if (*vid < vlan_start_vid(arr, *iterator))
			*vid = vlan_start_vid(arr, *iterator);
		
		uint16_t offset = vlan_offset(arr, *iterator) + ((*vid) - vlan_start_vid(arr, *iterator)) / 16;
		assert(offset < arr->numbitmap);

		uint16_t mask = 1 << ((*vid) % 16);
		int wasset = !!( arr->bitmap[offset] & mask);

		if (wasset)
			return 0;

		(*vid)++;
	}

	*vid = 0xffff;

	return 1;
}

size_t
vlan_dump(struct vlan_arr *arr, char *buf, size_t buflen)
{
	size_t written = 0;
	int it = 0;
	uint16_t vid = 0;

	if (buflen > 0)
		buf[0] = '\0';

	while (vlan_next(arr, &it, &vid) == 0 &&
	       written < buflen) {
		written += snprintf(buf + written, buflen - written, "%s%d", (written == 0 ? "" : ","), vid);
	}

	if (isdebug(DEBUG_GENERAL)) {
		char tmp[4096], *ptr;
		ptr = tmp;
		ptr += snprintf(ptr, tmp + sizeof(tmp) - ptr, "vlan %s(%p) numentries: %hu nummeta: %hu numbitmap: %hu\n",
				arr->name, arr, arr->numentries, arr->nummeta, arr->numbitmap);

		if (ptr < tmp + sizeof(tmp))
			ptr += snprintf(ptr, tmp + sizeof(tmp) - ptr, "meta:\n");
		for (uint16_t i = 0; i < arr->nummeta && ptr < tmp + sizeof(tmp); i++) {
			ptr += snprintf(ptr, tmp + sizeof(tmp) - ptr, " * %02d: start=%hhu offset=%hhu // startvid=%hu endvid=%hu\n", i, arr->meta[i].start, arr->meta[i].offset, vlan_start_vid(arr, i), vlan_end_vid(arr, i));
		}

		if (ptr < tmp + sizeof(tmp))
			ptr += snprintf(ptr, tmp + sizeof(tmp) - ptr, "bitmap:\n");
		for (uint16_t i = 0; i < arr->numbitmap && ptr < tmp + sizeof(tmp); i++) {
			ptr += snprintf(ptr, tmp + sizeof(tmp) - ptr, " * %02d: %04hx\n", i, arr->bitmap[i]);
		}

		eprintf(DEBUG_GENERAL, "%s", tmp);
	}

	return written;
}

struct vlan_arr *
vlan_alloc(const char *name)
{
	struct vlan_arr *ret = malloc(sizeof(*ret));
	assert(ret);
	memset(ret, 0, sizeof(*ret));
	
	if (name)
		strncpy(ret->name, name, sizeof(ret->name)-1);

	ret->numentries = 0;
	
	ret->nummeta = 0;
	ret->meta = NULL;

	ret->numbitmap = 0;
	ret->bitmap = NULL;

	return ret;
}

struct vlan_arr *
vlan_clone(struct vlan_arr *arr, const char *name)
{
	struct vlan_arr *ret = vlan_alloc(name);
	assert(ret);

	ret->numentries = arr->numentries;

	ret->nummeta = arr->nummeta;
	free(ret->meta);
	ret->meta = calloc(ret->nummeta, sizeof(*ret->meta));

	ret->numbitmap = arr->numbitmap;
	free(ret->bitmap);
	ret->bitmap = calloc(ret->numbitmap, sizeof(*ret->bitmap));

	if (ret->nummeta > 0) {
		assert(ret->meta);
		memcpy(ret->meta, arr->meta, ret->nummeta * sizeof(*ret->meta));
	}
	if (ret->numbitmap > 0) {
		assert(ret->bitmap);
		memcpy(ret->bitmap, arr->bitmap, ret->numbitmap * sizeof(*ret->bitmap));
	}

	return ret;
}

void
vlan_free(struct vlan_arr *arr)
{
	if (!arr)
		return;

	free(arr->meta);
	free(arr->bitmap);

	free(arr);
}

int
vlan_compare(struct vlan_arr *arr1, struct vlan_arr *arr2)
{
	int it1 = 0, it2 = 0;
	uint16_t vid1 = 0, vid2 = 0;
	int rc1, rc2;

	while (1) {
		rc1 = vlan_next(arr1, &it1, &vid1);
		rc2 = vlan_next(arr2, &it2, &vid2);

		if (rc1 != 0 && rc2 != 0)
			return 0; // success

		if (rc1 != 0 || rc2 != 0)
			return 1; // different number of vlans

		if (vid1 != vid2)
			return 1; // different vlan next
	}

	return 0;
}
