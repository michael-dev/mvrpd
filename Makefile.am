#include $(top_srcdir)/aminclude_static.am

sbin_PROGRAMS = mvrpd
check_PROGRAMS = test-vlan0
AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4
AM_CFLAGS = $(LIBNL_CFLAGS) $(LIBNLGENL_CFLAGS) $(LIBNLNF_CFLAGS) $(LIBNLROUTE_CFLAGS) -Wall -O2 -g -fPIE -std=gnu99 -Wall -Werror -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
LIBS += $(LIBNL_LIBS) $(LIBNLGENL_LIBS) $(LIBNLNF_LIBS) $(LIBNLROUTE_LIBS)

mvrpd_SOURCES = src/debug.c src/cmdline.c src/event.c src/main.c src/port.c src/bridge.c src/timer.c src/receive-nflog.c src/ether.c src/mvrp.c src/vlan.c src/random.c
test_vlan0_SOURCES = src/debug.c src/cmdline.c src/vlan.c src/test-vlan0.c
test_vlan0_CFLAGS = -fprofile-arcs -ftest-coverage
test_vlan0_LIBS = -fprofile-arcs -ftest-coverage

