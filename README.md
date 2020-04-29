Travis CI:
[![Build Status](https://secure.travis-ci.org/michael-dev/mvrpd.png?branch=master)](http://travis-ci.org/michael-dev/mvrpd)

Coverity Scan:
[![Coverity Scan Build Status](https://scan.coverity.com/projects/19020/badge.svg)](https://scan.coverity.com/projects/19020)

[![Total alerts](https://img.shields.io/lgtm/alerts/g/michael-dev/mvrpd.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/michael-dev/mvrpd/alerts/)

[![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/michael-dev/mvrpd.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/michael-dev/mvrpd/context:cpp)

mvrpd
=====

This daemon implements MVRP (supersedes GRVP) for linux bridges. It aims at automatically configuring vlans on links, especially inter-bride/inter-switch.

overview
--------

naive approach: 
  * Given a tree of network devices like an ethernet spanning tree.
  * The information of any device that is interested in a VLAN is then propagated until head of tree.
  * Any switch that has two or more ports that are interested in the same VLAN reports this information back to those ports interested in these VLANs and adds the VLAN to that port.

mvrp approach:
  * The switch records which ports are interested in a VLAN, either because they declared interest for a VLAN using MVRP or because it is configured manually.
  * The switch declares interest in a VLAN on each dynamic (MVRP-enabled) port, that indicates whether there are other ports on itself that also want this VLAN by registering for that VLAN.
  * If the bridge has two or more ports that are interested in a VLAN, it will activate (aka configure or register) the VLAN on all interested ports.

mvrpd
-----

This daemon scans a set of bridge ports (defaults to all non-dynamic and the bridge itself) for VLANs it is statically configured to be interested it.
Additionally, it listens on all dynamic (MVRP-enabled) ports for other devices or bridges interested in a VLAN.

If a bridge is interested in a VLAN, it registers for that VLAN on all dynamic ports. If a port is the only one interested in a VLAN, it is not registering for that VLAN (no loopback).

If a bridge as two or more ports that are interested in a VLAN, it will configure that VLAN on all interested ports.

Optionally, some VLANs may be skipped.

This daemon operates on vlan\_filtering enabled linux bridges.

cmdline
-------

  * --bridge <bridgename> (exactly once)
  * --uplinkif <pattern> : matches interfaces that are configured using MVRP (maybe repeated, takes precedence over --epif)
  * --epif <pattern> : matches interfaces that are statically configured (maybe repeated, ususally includes the bridge itself)
  * --ptpif <pattern> : matches interfaces. If those are configured by MVRP, it is assumed the at most one MVRP-enabled applicant (peer) is connected to this bridge port (e.g. another MVRP enabled bridge)
  * --ignore-vlan <vlan-id>: ignore this vlan id
  * --restrict-to-ep: only declare (announce) and thus register (configure) VLANs that are already added to the (statically configured) ports

Where pattern is matched using fnmatch, e.g. eth\* would match eth0, eth1, etc.

extra cmdline
-------------

  * --bridge-dump-netlink: dump netlink messages send/received in bridge module
  * --debug
  * --debug-all
  * --debug-bridge
  * --debug-ether
  * --debug-mvrp
  * --debug-nflog
  * --debug-port
  * --nflog-group: nflog group for MVRP snooping
  * --verbose

test-setup
----------

```
ip link add dev mvrp-bridge type bridge
ip link set dev mvrp-bridge type bridge vlan_filtering 1
ip link set dev mvrp-bridge type bridge vlan_default_pvid 0
ip link set dev mvrp-bridge up
bridge vlan add vid 300 dev mvrp-bridge self

for i in $(seq 0 10); do
  ip link add dev mvrp-p$i type veth peer name mvrp-c$i
  ip link set dev mvrp-p$i up
  ip link set dev mvrp-c$i up
  ip link add link mvrp-c$i name mvrp-c$i.100 type vlan id 100
  ip link set dev mvrp-c$i.100 type vlan mvrp on
  ip link set dev mvrp-c$i.100 up
  ip link set dev mvrp-p$i master mvrp-bridge
done

nft add table bridge nat
nft add chain bridge nat PREROUTING { type filter hook prerouting priority dstnat\; policy accept\; }
nft add rule bridge nat PREROUTING meta ibrname "mvrp-bridge" ether daddr 01:80:c2:00:00:21 log group 3 drop
```

```
for i in $(seq 0 10); do
 ip link set dev mvrp-p$i down
 ip link del dev mvrp-p$i
done
ip link set dev mvrp-bridge down
ip link del dev mvrp-bridge
```

