#ifndef _H_SEL4IP_H
#define _H_SEL4IP_H

#define SIOCSEL4IPDHCP	(SIOCPROTOPRIVATE+0x0)
#define SIOCSEL4IPPING	(SIOCPROTOPRIVATE+0x1)

#define SEL4IP_SOCKADDR_SIZE   128
#define SEL4IP_MAX_NAMESERVERS 4
#define SEL4IP_MAX_PING        10

typedef char sel4ip_sockaddr_t[SEL4IP_SOCKADDR_SIZE];

typedef struct sel4ip_ping_stat {
	unsigned long size;
	unsigned long seq;
	unsigned long ttl;
	unsigned long time;
	int           err;
} sel4ip_ping_stat_t;;

struct sel4ioctl {
	char ifname[16];
	union {
		struct {
			int               nameserver_count; /* result */
			sel4ip_sockaddr_t nameserver_addrs[SEL4IP_MAX_NAMESERVERS]; /* result, sockaddr_in or sockaddr_in6 */
		} dhcp;
		struct {
			int	               count; /* arg */
			sel4ip_sockaddr_t  addr; /* arg, sockaddr_in or sockaddr_in6 */
			sel4ip_ping_stat_t stats[SEL4IP_MAX_PING]; /* result */
		} ping;
	};
};

#endif
