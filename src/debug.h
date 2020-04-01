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

#ifndef MVRPD_DEBUG
#define MVRPD_DEBUG

#define DEBUG_ERROR       1
#define DEBUG_GENERAL     2
#define DEBUG_NFLOG       4
#define DEBUG_ETHER       8
#define DEBUG_BRIDGE     16
#define DEBUG_MVRP       32
#define DEBUG_VERBOSE    64
#define DEBUG_PORT      128
#define DEBUG_ALL       255

#include <stdio.h>

int isdebug(const int level);
void edprint(const int level, const char* msg, const char* file, const int line, const char* fnc);
#define eprintf(level, ...) { \
	if (isdebug(level)) { \
		char syslogbuf[81920];\
		snprintf(syslogbuf, sizeof(syslogbuf), __VA_ARGS__);\
		edprint(level, syslogbuf, __FILE__, __LINE__, __PRETTY_FUNCTION__);\
	};\
};

#endif

