#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <assert.h>

#include "debug.h"
#include "event.h"

struct ether_socket {
	int if_index;
	char if_name[IFNAMSIZ];
	char if_mac[ETH_ALEN];
	char mcast_mac[ETH_ALEN];
	int hwproto;
	int fd;
};

int ether_send(struct ether_socket *sock, const char* dst /* may be NULL */, const unsigned char *msg, size_t msglen) { 
	uint8_t *buf;
	size_t buf_len;
	int err;
	struct ether_header *eh;
	struct sockaddr_ll sock_addr;

	eprintf(DEBUG_ETHER,  "sending packet on %d len %zd", sock->if_index, msglen);

	if (!dst)
		dst = sock->mcast_mac;

	buf_len = sizeof(*eh) + msglen;
	if (buf_len > ETH_FRAME_LEN)
		return -EMSGSIZE;

	buf = malloc(buf_len);
	if (!buf)
		return -EMSGSIZE;
	memset (buf, 0, buf_len);
	
	eh = (struct ether_header *) buf;
	memcpy (eh->ether_shost, sock->if_mac, ETH_ALEN);
	memcpy (eh->ether_dhost, dst, ETH_ALEN);
	eh->ether_type = htons (sock->hwproto);

	memcpy(buf + sizeof(*eh), msg, msglen);

	memset (&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sll_ifindex = sock->if_index;
	sock_addr.sll_halen = ETH_ALEN;
	memcpy (sock_addr.sll_addr, dst, ETH_ALEN);

	err = sendto(sock->fd, buf, buf_len, 0,
		     (struct sockaddr *) &sock_addr, sizeof (sock_addr));
	if (err < 0) {
		eprintf(DEBUG_ERROR,  "sending packet failed: %s(%d)", strerror(errno), errno);
		goto out;
	}

	err = 0;

out:
	free(buf);
	
	return err;
}

static void ether_receive(int s, void *ctx)
{
	struct ether_socket *sock = ctx;
	struct sockaddr_ll client_addr;
	struct ether_header *eh;
	struct msghdr msg;
	struct iovec iov;
	uint8_t buf[ETH_FRAME_LEN], *payload;
	int hwproto;
	size_t bytes = 0, payloadlen = 0;

	memset(&msg, 0, sizeof(msg));
	memset(&client_addr, 0, sizeof(client_addr));
	memset(buf, 0, sizeof(buf));

	eprintf(DEBUG_ETHER,  "ether receive on %s(%d)", sock->if_name, sock->if_index);

	iov.iov_len = sizeof(buf);
	iov.iov_base = buf;
	msg.msg_name = &client_addr;
	msg.msg_namelen = sizeof(client_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	bytes = recvmsg(sock->fd, &msg, 0);

	if (bytes < sizeof(*eh))
		return;

	eh = (struct ether_header*) buf;
	hwproto = htons(eh->ether_type);
	if (hwproto != sock->hwproto) {
		eprintf(DEBUG_ETHER,  "ether...packet drop received proto=%x!=%x on %s(%d)", hwproto, sock->hwproto, sock->if_name, sock->if_index);
		return;
	}
	if (memcmp(eh->ether_dhost, sock->if_mac, ETH_ALEN) != 0 &&
	    memcmp(eh->ether_dhost, sock->mcast_mac, ETH_ALEN) != 0) {
		eprintf(DEBUG_ETHER, "ether...packet drop received proto=%x on %s(%d) daddr %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", hwproto, sock->if_name, sock->if_index, eh->ether_dhost[0], eh->ether_dhost[1], eh->ether_dhost[2], eh->ether_dhost[3], eh->ether_dhost[4], eh->ether_dhost[5]);
		return;
	}

	payload = buf + sizeof(*eh);
	payloadlen = bytes - sizeof(*eh);

	if (isdebug(DEBUG_ETHER)) {
		eprintf(DEBUG_ETHER,  "ether...packet received proto=%x on %s(%d)", hwproto, sock->if_name, sock->if_index);
		fprintf(stderr, "payload = ");
		for (int i = 0; i < payloadlen; i++)
		{
			fprintf(stderr, "%s%02x", (i > 0 ? ":" : ""),  payload[i]);
		}
		fprintf(stderr, "\n");
	}

	cb_call_packet_cb(hwproto, payload, payloadlen, sock->if_name, sock->if_index);
}

void ether_close(struct ether_socket *sock) {
	if (!sock)
		return;
	cb_del_handle(sock->fd, sock, ether_receive);
	close(sock->fd);
	free(sock);
}

struct ether_socket *
ether_listen(int if_index, const char *if_name, const char *if_mac, int hwproto, const char* mcast_mac)
{
	struct packet_mreq multicast_req;
	struct sockaddr_ll addr;
	int err, fd;
	struct ether_socket *sock = NULL;

	eprintf(DEBUG_ETHER,  "listening for packets on %s(%d) type %04x mcast %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx", if_name, if_index, hwproto,
			mcast_mac[0],mcast_mac[1],mcast_mac[2],mcast_mac[3],mcast_mac[4],mcast_mac[5]);

	/* filtering for hwproto did not work for me, ETH_P_ALL works but will result in a load problem as tagged packets are received as well */
	//fd = socket (PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	fd = socket (PF_PACKET, SOCK_RAW, htons(hwproto));
  	if (fd < 0)
		goto errout;
	memset(&addr, 0, sizeof(addr));
	addr.sll_ifindex = if_index;
	addr.sll_family = AF_PACKET;
	//addr.sll_protocol = htons(ETH_P_ALL);
	addr.sll_protocol = htons(hwproto);

	err = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (err < 0)
		goto errout;

	memset(&multicast_req, 0, sizeof(multicast_req));;
	multicast_req.mr_ifindex = if_index;
	multicast_req.mr_type = PACKET_MR_MULTICAST;
	multicast_req.mr_alen = ETH_ALEN;
	memcpy(multicast_req.mr_address, mcast_mac, ETH_ALEN);
	err = setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
			 &multicast_req, sizeof(multicast_req));
	if (err < 0)
		goto errout;

	sock = malloc(sizeof(*sock));
	assert(sock);
	sock->if_index = if_index;
	strncpy(sock->if_name, if_name, sizeof(sock->if_name) - 1);
	memcpy(sock->if_mac, if_mac, ETH_ALEN);
	memcpy(sock->mcast_mac, mcast_mac, ETH_ALEN);
	sock->hwproto = hwproto;
	sock->fd = fd;

	/* for unkown reasons this is not called ... */
	cb_add_handle(fd, sock, ether_receive);

	return sock;

errout:
	eprintf(DEBUG_ERROR, "ether socket error: %s(%d)", strerror(errno), errno );
	if (fd >= 0)
		close(fd);
	return NULL;
}
