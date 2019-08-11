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
#include "event.h"
#include "debug.h"
#include <stdio.h>

int main(int argc, char *argv[])
{
	#ifdef REV
	fprintf(stderr, "mvrpd version svn-%s\n", REV);
	#else
	fprintf(stderr, "mvrpd version $Id$\n");
	#endif

	parse_cmdline(argc, argv);
	event_runloop();
}
