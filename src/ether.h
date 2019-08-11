#include <stddef.h>

struct ether_socket;

int ether_send(struct ether_socket *sock, const char* dst /* may be NULL */, const unsigned char *msg, size_t msglen); 
void ether_close(struct ether_socket *sock);
struct ether_socket *
ether_listen(int if_index, const char *if_name, const char *if_mac, int hwproto, const char* mcast_addr);

