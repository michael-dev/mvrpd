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
#include "event.h"
#include "debug.h"
#include "mvrp.h"
#include "timer.h"
#include "ether.h"
#include "port.h"
#include "vlan.h"
#include "random.h"

#include <assert.h>
#include <string.h>
#include <arpa/inet.h>

#define MIN(a,b,c,d) ( \
                ( a <= b && a <= c && a <= d ) ? a : \
                ( b <= a && b <= c && b <= d ) ? b : \
                ( c <= a && c <= b && c <= d ) ? c : \
                d )

const time_t leaveAllInterval = 60;
const time_t leaveTimeout = 5; // at least, at most twice
const time_t periodicSendInterval = 10;
const time_t gracePeriodForRemoteLeaveAll = 10;

struct mrpdu_message {
        uint8_t AttributeType;
        uint8_t AttributeLength;        /* length of FirstValue */
} __attribute__((packed));

struct mrpdu {
        uint8_t ProtocolVersion;
        /* mrpdu could have trailing NULL (0x0000) indicating the ENDMARK */
} __attribute__((packed));

struct mrpdu_vectorattrib {
        uint16_t VectorHeader;  /* LeaveAllEvent << 13 | NumberOfValues */
} __attribute__((packed));

enum mvrp_event {
        MVRP_EV_NEW     = 0,
        MVRP_EV_JOININ  = 1,
        MVRP_EV_IN      = 2,
        MVRP_EV_JOINMT  = 3,
        MVRP_EV_MT      = 4,
        MVRP_EV_LV      = 5,
        _MVRP_EV_MAX
};

struct mvrp_build_state {
        unsigned int changes:1;
        unsigned int notempty:1;
};

static const char mvrp_addr[6] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x21 };
static const char MVRP_PROTO_VERSION = 0x00;
static const char MVRP_VID_ATTR_LEN = 0x02;
static const char MVRP_VID_ATTR_TYPE = 0x01;

static void _mvrp_send(struct if_entry *port, int leaveAll, int force);

static void
mvrp_do_leaveall(struct if_entry *port)
{

        vlan_free(port->vlan_declared_remote_leave);
        port->vlan_declared_remote_leave = vlan_clone(port->vlan_declared_remote, "port->drl");
        port->needSend = 1;
}

static void
mvrp_handle_leaveall(struct if_entry *port)
{
        if (!port)
                return;

        struct timespec tv;
        clock_gettime(CLOCK_MONOTONIC, &tv);
        port->lastLeaveAll = tv.tv_sec;
        port->lastLeaveAllFromMe = 0;
        mvrp_do_leaveall(port);
        eprintf(DEBUG_MVRP, "received leaveAll on port %s(%d) [type=%d], trigger sending", port->ifname, port->ifidx, port->type);
}

static const char *
mvrp_event2str(int event)
{
        switch (event) {
                case MVRP_EV_NEW:
                        return "NEW";
                case MVRP_EV_JOININ:
                        return "JOININ";
                case MVRP_EV_IN:
                        return "IN";
                case MVRP_EV_JOINMT:
                        return "JOINMT";
                case MVRP_EV_MT:
                        return "MT";
                case MVRP_EV_LV:
                        return "LV";
                default:
                        return "??";
        }
}

static void
mvrp_handle_vlan_event(struct if_entry *port, int event, int vid)
{
        if (!port)
                return;
        assert(port->type == IF_MVRP);

        switch (event) {
        case MVRP_EV_JOININ:
        case MVRP_EV_JOINMT:
        case MVRP_EV_NEW:
                vlan_set(port->vlan_declared_remote, vid);
                vlan_unset(port->vlan_declared_remote_leave, vid);
                vlan_unset(port->vlan_declared_remote_leave2, vid);
                break;
        case MVRP_EV_LV:
                if (!port->ptp) {
                        vlan_set(port->vlan_declared_remote_leave, vid);
                        if (vlan_test(port->vlan_declared_local, vid))
                                port->needSend = 1;
                        break;
                }
        case MVRP_EV_IN:
        case MVRP_EV_MT:
                if (!port->ptp)
                        break;
                vlan_unset(port->vlan_declared_remote, vid);
        }

        switch (event) {
        case MVRP_EV_JOININ:
        case MVRP_EV_IN:
                vlan_set(port->vlan_registered_remote, vid);
                break;
        case MVRP_EV_LV:
                if (!port->ptp)
                        break;
        case MVRP_EV_JOINMT:
        case MVRP_EV_MT:
        case MVRP_EV_NEW:
                vlan_unset(port->vlan_registered_remote, vid);
                break;
        }
}

static void
mvrp_parse_event(struct if_entry *port, const int attrtype, const int attrlen, const unsigned char* firstval, int idx, int event)
{
        if (attrtype != MVRP_VID_ATTR_TYPE) {
                eprintf(DEBUG_MVRP,  "MVRP unknown attribute type %d", attrtype);
                return; /* invalid type, see IEE 802.1q-2018 11.2.3.1.6 */
        }
        if (attrlen != MVRP_VID_ATTR_LEN) {
                eprintf(DEBUG_MVRP,  "MVRP bad vid attribute len %d", attrlen);
                return; /* invalid length, see IEEE 802.1q-2018 11.2.3.1.8 */
        }

        uint16_t vid;
        assert(attrlen == sizeof(vid));
        memcpy(&vid, firstval, sizeof(vid));
        vid = ntohs(vid) + idx;

        eprintf(DEBUG_MVRP,  "MVRP:       * trigger event %s(%d) vid %d", mvrp_event2str(event), event, vid);
        mvrp_handle_vlan_event(port, event, vid);
}

/*
 * returns the number of bytes consumed or
 * zero for non-recoverable error
 *
 * note: endmark has length 2, all others length > 2
 */
static size_t
mvrp_parse_vecattr(struct if_entry *port, const int attrtype, const int attrlen, const unsigned char* msgbuf, size_t bytes, int *leaveAllDone)
{
        const struct mrpdu_vectorattrib *mrpdu_vec = NULL;
        size_t consumed = 0;

        /* test for endmark */
        if (bytes >= 2 &&
            msgbuf[0] == 0x00 &&
            msgbuf[1] == 0x00) {
                return 2;
        }

        if (bytes < sizeof(*mrpdu_vec)) {
                eprintf(DEBUG_MVRP,  "MVRP vector header too short");
                return 0;
        }

        mrpdu_vec = (struct mrpdu_vectorattrib *) msgbuf;
        consumed += sizeof(*mrpdu_vec);

        eprintf(DEBUG_MVRP, "vector header = %04hx at %p", mrpdu_vec->VectorHeader, mrpdu_vec);
        const int leaveAllEvent = (ntohs(mrpdu_vec->VectorHeader) / 8192 == 1);
        const int numOfValues = ntohs(mrpdu_vec->VectorHeader) % 8192;

        const unsigned char* firstValue = msgbuf + consumed; // attrlen bytes
        consumed += attrlen;

        if (isdebug(DEBUG_MVRP)) {
                char buf[4096];
                char *ptr = buf;

                for (int i = 0; i < attrlen && ptr < buf + sizeof(buf); i++)
                        ptr += snprintf(ptr, buf + sizeof(buf) - ptr, "%s%02hhx", (i > 0 ? ":" : ""), firstValue[i]);
                ptr[0] = '\0';

                eprintf(DEBUG_MVRP,  "MVRP:     * vector leaveAllEvent=%d numOfValues=%d firstValue=%s%s", leaveAllEvent, numOfValues, (attrlen == 1 ? "0x" : ""), buf);
        }

        const unsigned char *vector = msgbuf + consumed;

        if (leaveAllEvent == 0x1 && !(*leaveAllDone)) {
                mvrp_handle_leaveall(port);
                *leaveAllDone = 1;
        }

        // vector can be either fourpackedevents or threepackedevents
        // MVRP only used threepackedevents
        int attridx = 0;
        int numOfValuesRemaining = numOfValues;
        while (numOfValuesRemaining > 0 && bytes > consumed) {
                int event;
                uint8_t val = *vector;
                consumed++;
                vector++;

                event = (val / 36) % 6;
                mvrp_parse_event(port, attrtype, attrlen, firstValue, attridx, event);
                attridx++;
                numOfValuesRemaining--;

                if (numOfValuesRemaining == 0)
                        break;

                event = (val /  6) % 6;
                mvrp_parse_event(port, attrtype, attrlen, firstValue, attridx, event);
                attridx++;
                numOfValuesRemaining--;

                if (numOfValuesRemaining == 0)
                        break;

                event = (val /  1) % 6;
                mvrp_parse_event(port, attrtype, attrlen, firstValue, attridx, event);
                attridx++;
                numOfValuesRemaining--;
        }

        if (numOfValuesRemaining > 0) {
                eprintf(DEBUG_MVRP,  "MVRP pdu too short for vector numOfValues=%d remaining=%d vectorBytes=%zd", numOfValues, numOfValuesRemaining, msgbuf + consumed - vector);
                return 0; // numOfValues bigger than message length provides
        }

        return consumed;
}

/*
 * returns the number of bytes consumed or
 * zero for non-recoverable error
 *
 * note: endmark has length 2, all others length > 2
 */
static size_t
mvrp_parse_msg(struct if_entry *port, const unsigned char *msgbuf, size_t bytes)
{
        const struct mrpdu_message *mrpdu_msg = NULL;
        size_t consumed = 0;
        int leaveAllDone = 0;

        /* test for endmark */
        if (bytes >= 2 &&
            msgbuf[0] == 0x00 &&
            msgbuf[1] == 0x00) {
                return 2;
        }

        if (bytes < sizeof(*mrpdu_msg)) {
                eprintf(DEBUG_MVRP,  "MVRP message too short");
                return 0;
        }

        mrpdu_msg = (struct mrpdu_message *) msgbuf;
        consumed += sizeof(*mrpdu_msg);

        const int attrtype = mrpdu_msg->AttributeType;
        const int attrlen = mrpdu_msg->AttributeLength;

        eprintf(DEBUG_MVRP,  "MVRP:   * attrtype=%d attrlen=%d", attrtype, attrlen);
        while (consumed < bytes) {
                eprintf(DEBUG_MVRP,  "MVRP:   parse another vector chunk with %zd bytes left", bytes - consumed);
                size_t rc = mvrp_parse_vecattr(port, attrtype, attrlen, msgbuf + consumed, bytes - consumed, &leaveAllDone);
                consumed += rc;
                if (rc == 0)
                        return 0;
                if (rc == 2)
                        break; // endmark
        }

        return consumed;
}

static int
mvrp_parse_pdu(struct if_entry *port, const unsigned char *msgbuf, size_t bytes)
{
        const struct mrpdu *mrpdu;
        const unsigned char *mrpdu_msg_ptr;
        const unsigned char *mrpdu_msg_eof;

        if (bytes < sizeof(*mrpdu))
                return -1;

        mrpdu = (struct mrpdu *) msgbuf;

        /*
         * This is the first version of the protocol.
         * Wenn shall parse older versions as well if supported, and can parse
         * never versions accoring to our version specification.
         */

        eprintf(DEBUG_MVRP,  "MVRP: protocol version %hhd", mrpdu->ProtocolVersion);
        if (mrpdu->ProtocolVersion != MVRP_PROTO_VERSION)
                eprintf(DEBUG_MVRP,  "MVRP: different protocol version %hhd != %hhd", mrpdu->ProtocolVersion, MVRP_PROTO_VERSION);

        mrpdu_msg_ptr = msgbuf  + sizeof(*mrpdu);
        mrpdu_msg_eof = msgbuf + bytes;

        while (mrpdu_msg_ptr < mrpdu_msg_eof) {
                eprintf(DEBUG_MVRP,  "MVRP: parse another msg chunk with %zd bytes left", mrpdu_msg_eof - mrpdu_msg_ptr);
                size_t rc = mvrp_parse_msg(port, mrpdu_msg_ptr, mrpdu_msg_eof - mrpdu_msg_ptr);
                mrpdu_msg_ptr += rc;
                if (rc == 0)
                        return -1;
                if (rc == 2) /* end mark encountered */
                        break;
        }

        assert(mrpdu_msg_ptr <= mrpdu_msg_eof);

        if (mrpdu_msg_ptr < mrpdu_msg_eof)
                eprintf(DEBUG_MVRP,  "MVRP got junk at the end: %zd bytes left over", (mrpdu_msg_eof - mrpdu_msg_ptr));

        return 0;
}

static void
mvrp_got_packet(const int ptype, const unsigned char *packet, const int len, const char* ifname, const int ifindex)
{
        if (ptype != ETH_P_MVRP) {
                eprintf(DEBUG_MVRP,  "packet is not MVRP");
                return;
        }

        struct if_entry *port = port_get_by_ifidx(ifindex);
        if (!port || port->type != IF_MVRP) {
                eprintf(DEBUG_MVRP,  "port %s(%d) not listening, maybe due to NFLOG", ifname, ifindex);
                return;
        }

        eprintf(DEBUG_MVRP, "receive on port %s(%d) [type=%d]", port->ifname, port->ifidx, port->type);
        int rc = mvrp_parse_pdu(port, packet, len);
        if (rc < 0)
                eprintf(DEBUG_ERROR,  "MVRP: bad packet ignored");
        eprintf(DEBUG_MVRP,  "MVRP ACK processing finished");

        if (port->needSend)
                _mvrp_send(port, 0, 1);

        port_vlan_changed();
}

static size_t
mvrp_build_endmark(unsigned char *msgbuf, size_t bytes)
{
        if (bytes < 2)
                return 0;
        memset(msgbuf, 0, 2);
        return 2;
}

static void
mvrp_write_vec_header(struct mrpdu_vectorattrib *mrpdu_vec, int leaveAll, int numOfValues)
{
        uint16_t val = (numOfValues % 8192);
        if (leaveAll)
                val += 8192;
        mrpdu_vec->VectorHeader = htons(val);
}

static size_t
mvrp_build_msg(struct if_entry *port, int leaveAll, unsigned char *msgbuf, size_t bytes, struct mvrp_build_state *ret)
{
        struct mrpdu_message *mrpdu_msg = NULL;
        struct mrpdu_vectorattrib *mrpdu_vec = NULL;
        size_t len = 0;
        int numOfValues = 0;
        void *firstValue = NULL;

        if (bytes < sizeof(*mrpdu_msg))
                return 0;

        eprintf(DEBUG_MVRP, "add mrpdu_message header at 0");
        mrpdu_msg = (struct mrpdu_message *) msgbuf;
        len += sizeof(*mrpdu_msg);

        mrpdu_msg->AttributeType = MVRP_VID_ATTR_TYPE;
        mrpdu_msg->AttributeLength = MVRP_VID_ATTR_LEN;

        if (bytes - len < sizeof(*mrpdu_vec)) {
                eprintf(DEBUG_MVRP,  "MVRP vector header too short");
                return 0;
        }

        eprintf(DEBUG_MVRP, "add mrpdu_vector header at %zu", len);
        mrpdu_vec = (struct mrpdu_vectorattrib *) (msgbuf + len);
        len += sizeof(*mrpdu_vec);
        numOfValues = 0;
        eprintf(DEBUG_MVRP, "  update vector header at %zu with leaveAdd=%d numOfValues=%d", (((size_t) mrpdu_vec) - ((size_t) msgbuf)), leaveAll, numOfValues);
        mvrp_write_vec_header(mrpdu_vec, leaveAll, numOfValues);

        eprintf(DEBUG_MVRP, "add firstvalue at %zu", len);
        firstValue = (void*) (msgbuf + len);
        len += 2;

        ret->changes = ret->changes || leaveAll;
        ret->notempty = ret->notempty || leaveAll;

        int itdo = 0, itdn = 0, itro = 0, itrn = 0;
        uint16_t viddo = 0, viddn = 0, vidro = 0, vidrn = 0;
        uint16_t vid = MIN(viddo, viddn, vidro, vidrn);
        uint16_t lastvid = 0;
        uint8_t *vecitem = NULL; // make compiler quiet by initializing to NULL

        while (vid != 0xffff) {
                while (viddo <= vid)
                        vlan_next(port->vlan_declared_local_lastSend, &itdo, &viddo);
                while (viddn <= vid)
                        vlan_next(port->vlan_declared_local, &itdn, &viddn);
                while (vidro <= vid)
                        vlan_next(port->vlan_registered_local_lastSend, &itro, &vidro);
                while (vidrn <= vid)
                        vlan_next(port->vlan_registered_local, &itrn, &vidrn);

                vid = MIN(viddo, viddn, vidro, vidrn);
                if (vid == 0xffff)
                        break;
                eprintf(DEBUG_MVRP, "add vid %hu, declaration: old=%d new=%d, registration: old=%d, new=%d",
                                vid, (viddo == vid), (viddn == vid), (vidro == vid), (vidrn == vid));

                if (lastvid == 0) {
                        uint16_t tmp = htons(vid);
                        memcpy(firstValue, &tmp, sizeof(tmp));
                        lastvid = vid - 1;
                } else if (vid - lastvid > 12) {
                        /* each unneccessarely added VLAN adds 8/3 bits
                         * an extra vector header costs 16 bit + 16 bit firstval
                         * so after 32 / (8/3) = 12 unset vlans -> use new vector */
                        /* create a new vector header */
                        eprintf(DEBUG_MVRP, "add mrpdu_vector header at %zu", len);
                        mrpdu_vec = (struct mrpdu_vectorattrib *) (msgbuf + len);
                        len += sizeof(*mrpdu_vec);
                        if (len > bytes)
                                return 0;

                        numOfValues = 0;
                        eprintf(DEBUG_MVRP, "  update vector header at %zu with leaveAdd=%d numOfValues=%d", (((size_t)mrpdu_vec) - ((size_t)msgbuf)), leaveAll, numOfValues);
                        mvrp_write_vec_header(mrpdu_vec, leaveAll, numOfValues);

                        eprintf(DEBUG_MVRP, "add firstvalue at %zu", len);
                        firstValue = (void*) (msgbuf + len);
                        len += 2;
                        if (len > bytes)
                                return 0;
                        uint16_t tmp = htons(vid);
                        memcpy(firstValue, &tmp, sizeof(tmp));
                        lastvid = vid - 1;
                }

                ret->notempty = 1;

                while (lastvid < vid) {
                        lastvid++;

                        int event;
                        if (lastvid == vid) {
                                if (viddo == vid && viddn != vid)
                                        event = MVRP_EV_LV; // was declared but not longer is
                                else if (viddn == vid && vidrn == vid)
                                        event = MVRP_EV_JOININ; // declared and registered
                                else if (viddn == vid && vidrn != vid)
                                        event = MVRP_EV_JOINMT; // declared but not registered
                                else if (viddn != vid && vidrn == vid)
                                        event = MVRP_EV_IN; // not declared but registered
                                else if (viddn != vid && vidrn != vid)
                                        event = MVRP_EV_MT; // not declared and not registered
                                else {
                                        eprintf(DEBUG_ERROR, "ups viddo=%d viddn=%d vidro=%d vidrn=%d vid=%d", viddo,viddn, vidro, vidrn, vid);
                                        event = MVRP_EV_MT;
                                }
                                ret->changes = ret->changes || (viddn == vid && viddo != vid); // declaration changed
                                ret->changes = ret->changes || (viddn != vid && viddo == vid); // declaration changed
                                ret->changes = ret->changes || (vidrn == vid && vidro != vid); // registration changed
                                ret->changes = ret->changes || (vidrn != vid && vidro == vid); // registration changed
                        } else {
                                // lastvid is in no list, so neither declared nor registered
                                event = MVRP_EV_MT;
                        }

                        switch (numOfValues % 3) {
                        case 0:
                                eprintf(DEBUG_MVRP, " move vecitem to %zu", len);
                                vecitem = msgbuf + len;
                                len++;
                                if (len > bytes)
                                        return 0;
                                *vecitem += 36 * event;
                                break;
                        case 1:
                                assert(vecitem);
                                *vecitem += 6 * event;
                                break;
                        case 2:
                                assert(vecitem);
                                *vecitem += 1 * event;
                                break;
                        }

                        eprintf(DEBUG_MVRP, "  wrote event for %hu at %zu = %zu", lastvid, (vecitem - msgbuf), len-1);
                        numOfValues++;
                }

                eprintf(DEBUG_MVRP, "  update vector header at %zu with leaveAdd=%d numOfValues=%d", (((size_t)mrpdu_vec) - ((size_t)msgbuf)), leaveAll, numOfValues);
                mvrp_write_vec_header(mrpdu_vec, leaveAll, numOfValues);
        }

        size_t rc = mvrp_build_endmark(msgbuf + len, bytes - len);
        if (rc == 0) {
                eprintf(DEBUG_ERROR, "failed to add endmark to end of MVRP list of vector");
                return 0;
        }
        len += rc;

        return len;
}

static size_t
mvrp_build_pdu(struct if_entry *port, int leaveAll, unsigned char *msgbuf, size_t bytes, struct mvrp_build_state *ret)
{
        struct mrpdu *mrpdu;
        size_t len = 0, rc;

        if (bytes < sizeof(*mrpdu))
                return -1;

        mrpdu = (struct mrpdu *) msgbuf;
        len += sizeof(*mrpdu);

        mrpdu->ProtocolVersion = MVRP_PROTO_VERSION;

        rc = mvrp_build_msg(port, leaveAll, msgbuf + len, bytes - len, ret);
        if (rc == 0)
                return 0;
        len += rc;

        rc = mvrp_build_endmark(msgbuf + len, bytes - len);
        if (rc == 0)
                eprintf(DEBUG_ERROR, "failed to add endmark to end of MVRP message");
        len += rc;

        return len;
}

void
mvrp_send(struct if_entry *port)
{
        _mvrp_send(port, 0, 0);
}

static void
_mvrp_send(struct if_entry *port, int leaveAll, int force)
{
        unsigned char packet[ETH_FRAME_LEN - sizeof(struct ether_header)];
        memset(packet, 0, sizeof(packet));

        eprintf(DEBUG_MVRP, "send on port %s(%d) [type=%d] leaveAll=%d force=%d", port->ifname, port->ifidx, port->type, leaveAll, force);

        struct mvrp_build_state ret = { };
        size_t len = mvrp_build_pdu(port, leaveAll, packet, sizeof(packet), &ret);
        if (len == 0) {
                eprintf(DEBUG_ERROR,  "MVRP: failed to build packet");
                return;
        }
        if (!ret.notempty) {
                eprintf(DEBUG_VERBOSE,  "MVRP: failed to build packet - nothing to send on %s(%d)", port->ifname, port->ifidx);
                return;
        }
	if (vlan_compare(port->vlan_registered_local, port->vlan_registered_remote)) {
                char buf[4096];
                int rc;
                eprintf(DEBUG_VERBOSE, "inconsistent state for registered vlans on local and remote side %s(%d)", port->ifname, port->ifidx);
                rc = (sizeof(buf) == vlan_dump(port->vlan_registered_local, buf, sizeof(buf)));
                eprintf(DEBUG_VERBOSE, " * local registered vlans %s%s", buf, rc ? "...":"");
                rc = (sizeof(buf) == vlan_dump(port->vlan_registered_remote, buf, sizeof(buf)));
                eprintf(DEBUG_VERBOSE, " * remote registered vlans %s%s", buf, rc ? "...":"");

		force = 1; // force sending
	}
        if (!force && !ret.changes) {
                eprintf(DEBUG_MVRP, "skip sending packet as nothing changed on port %s(%d)", port->ifname, port->ifidx);
                return;
        }
        if (isdebug(DEBUG_MVRP)) {
                char buf[4096];
                int rc;
                rc = (sizeof(buf) == vlan_dump(port->vlan_declared_local, buf, sizeof(buf)));
                eprintf(DEBUG_MVRP, "send packet declaring vlans %s%s", buf, rc ? "...":"");
                rc = (sizeof(buf) == vlan_dump(port->vlan_registered_local, buf, sizeof(buf)));
                eprintf(DEBUG_MVRP, "send packet registered vlans %s%s", buf, rc ? "...":"");
                rc = (sizeof(buf) == vlan_dump(port->vlan_declared_local_lastSend, buf, sizeof(buf)));
                eprintf(DEBUG_MVRP, "send packet declaring vlans lastSend %s%s", buf, rc ? "...":"");
                rc = (sizeof(buf) == vlan_dump(port->vlan_registered_local_lastSend, buf, sizeof(buf)));
                eprintf(DEBUG_MVRP, "send packet registered vlans lastSend %s%s", buf, rc ? "...":"");

                eprintf(DEBUG_MVRP, "send packet (start)");
                rc = mvrp_parse_pdu(NULL, packet, len);
                eprintf(DEBUG_MVRP, "send packet (end)");
                if (rc < 0) {
                        eprintf(DEBUG_ERROR,  "MVRP: bad packet generated");
                }
        }
        ether_send(port->sock, NULL, packet, len);

        // record changes
        vlan_free(port->vlan_registered_local_lastSend);
        port->vlan_registered_local_lastSend = vlan_clone(port->vlan_registered_local, "port->vrlS");

        vlan_free(port->vlan_declared_local_lastSend);
        port->vlan_declared_local_lastSend = vlan_clone(port->vlan_declared_local, "port->vdllS");

        port->needSend = 0;
        struct timespec tv;
        clock_gettime(CLOCK_MONOTONIC, &tv);
        port->lastSent = tv.tv_sec;
}

struct ether_socket *
mvrp_listen(int if_index, const char *if_name, const char *if_mac)
{
        return ether_listen(if_index, if_name, if_mac, ETH_P_MVRP, mvrp_addr);
}

void
mvrp_close(struct ether_socket *sock)
{
        return ether_close(sock);
}

static void
mvrp_timer_leave_cb(struct if_entry *port, void *ctx)
{
        struct timespec *now = ctx;
        if (port->type != IF_MVRP)
                return;
        if (port->lastLeaveTimer + leaveTimeout > now->tv_sec)
                return;
        port->lastLeaveTimer = now->tv_sec;

        if (isdebug(DEBUG_MVRP)) {
                char buf[4096];
                int rc;
                rc = (sizeof(buf) == vlan_dump(port->vlan_declared_remote_leave2, buf, sizeof(buf)));
                eprintf(DEBUG_MVRP, "discard remote vlans due to leaveTimer timing out for vlans %s%s", buf, rc ? "...":"");
	}

        int it = 0;
        uint16_t vid = 0;
        while (vlan_next(port->vlan_declared_remote_leave2, &it, &vid) == 0) {
                vlan_unset(port->vlan_declared_remote, vid);
                vlan_unset(port->vlan_registered_remote, vid);
        }
        vlan_free(port->vlan_declared_remote_leave2);
        port->vlan_declared_remote_leave2 = port->vlan_declared_remote_leave;
        port->vlan_declared_remote_leave = vlan_alloc("port->vdrl");
}

static void
mvrp_timer_leaveAll_cb(struct if_entry *port, void *ctx)
{
        struct timespec *now = ctx;
	int gracePeriod = 0;

        if (port->type != IF_MVRP)
                return;
	if (!port->lastLeaveAllFromMe)
                gracePeriod += (gracePeriodForRemoteLeaveAll / 2);
       	gracePeriod += getrandom(gracePeriodForRemoteLeaveAll / 2);

        if (port->lastLeaveAll + leaveAllInterval + gracePeriod > now->tv_sec)
                return;
        port->lastLeaveAll = now->tv_sec;
        port->lastLeaveAllFromMe = 1;
        eprintf(DEBUG_VERBOSE, "send periodic leaveAll on port %s(%d) [type=%d]", port->ifname, port->ifidx, port->type);
        mvrp_do_leaveall(port);
        _mvrp_send(port, 1, 1);
}

static void
mvrp_timer_periodic_send_cb(struct if_entry *port, void *ctx)
{
        struct timespec *now = ctx;
        if (port->type != IF_MVRP)
                return;
        if (port->lastSent + periodicSendInterval > now->tv_sec &&
            !port->needSend)
                return;
        _mvrp_send(port, 0, 1);
}

static void
mvrp_timer(void *ctx)
{
        struct timespec tv;
        clock_gettime(CLOCK_MONOTONIC, &tv);
        for_each_port(mvrp_timer_leave_cb, &tv);

        for_each_port(mvrp_timer_leaveAll_cb, &tv);

        port_vlan_changed();

        for_each_port(mvrp_timer_periodic_send_cb, &tv);
}

static __attribute__((constructor)) void mvrp_init()
{
        cb_add_packet_cb(mvrp_got_packet);
        cb_add_timer(1, 1, NULL, mvrp_timer);
}

