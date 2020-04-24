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
#include "random.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <math.h>

// random uniform in [0; max)
int getrandom(const int max)
{
       if (max <= 0)
	       return 0;

       double r = (double)rand();
       double m = (double)(RAND_MAX);
       return floor(r * max / (m+1.0));
}

static __attribute__((constructor)) void random_init()
{
       srand(time(0));
}

