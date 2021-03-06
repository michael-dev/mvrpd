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
#include "cmdline.h"
#include "debug.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct option_cb_entry {
	struct option option;
	option_cb cb;
	void *cbarg;
	struct option_cb_entry* next;
};

static struct option_cb_entry* globalOptionCb = NULL;
static int globalOptionCbSize = 0;

void add_option_cb(struct option opt, option_cb cb, void *cbarg) {
	struct option_cb_entry* entry = malloc(sizeof(struct option_cb_entry));
	if (!entry) {
		eprintf(DEBUG_ERROR, "out of memory at %s:%d in %s", __FILE__, __LINE__, __PRETTY_FUNCTION__);
		exit(1);
	}
	memcpy(&entry->option, &opt, sizeof(opt));
	entry->cb = cb;
	entry->cbarg = cbarg;
	entry->next = globalOptionCb;
	globalOptionCb = entry;
	globalOptionCbSize++;
}

void parse_cmdline(int argc, char *argv[])
{
	struct option *long_options = calloc(globalOptionCbSize + 1, sizeof(struct option));
	struct option_cb_entry **option_cbs = calloc(globalOptionCbSize, sizeof(*option_cbs));
	int i=0;
	for(struct option_cb_entry *entry = globalOptionCb; entry; entry = entry->next, i++) {
		memcpy(&long_options[i], &entry->option, sizeof(entry->option));
		option_cbs[i] = entry;
	}

	int option_index = 0;
	int c;
	while ((c = getopt_long (argc, argv, "", long_options, &option_index)) != -1) {
		if (c == '?') {
			eprintf(DEBUG_ERROR, "%s:%d %s error parsing command line", __FILE__, __LINE__, __PRETTY_FUNCTION__);
			exit(1);
		}
		if (option_index < 0 || option_index >= globalOptionCbSize) {
			eprintf(DEBUG_ERROR, "%s:%d %s error parsing command line - invalid index returned", __FILE__, __LINE__, __PRETTY_FUNCTION__);
			exit(1);
		}
		struct option_cb_entry *entry = option_cbs[option_index];
		entry->cb(c, entry->cbarg);
	}
	free (option_cbs);
	free (long_options);
}
