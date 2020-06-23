/*********************************************************************
PicoTCP. Copyright (c) 2013 TASS Belgium NV. Some rights reserved.
See LICENSE and COPYING for usage.
Do not redistribute without a written permission by the Copyright
holders.

Author: Andrei Carp, Maxime Vincent
*********************************************************************/
#include "pico_defines.h"
#include <linux/types.h>
#include "pico_addressing.h"
#include "pico_constants.h"
#include "pico_config.h"
#include "pico_stack.h"
#include "pico_icmp4.h"
#include "pico_stack.h"
#include "pico_ipv4.h"
#include "pico_ipv6.h"
#include "pico_dns_client.h"
#include "pico_socket.h"
#include "pico_device.h"
#include "pico_stack.h"
#include "pico_tree.h"
#include "pico_socket.h"
#include "pico_protocol.h"
#include "pico_queue.h"
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <linux/if_arp.h>
#include <linux/socket.h>

#ifndef PICO_BSD_SOCKETS_H_
#define PICO_BSD_SOCKETS_H_
#define SOCKSIZE  16
#define SOCKSIZE6 28

extern wait_queue_head_t picotcp_stack_init_wait;

#define PICO_WAIT_INIT() \
  DEFINE_WAIT(wait); \
  prepare_to_wait(&picotcp_stack_init_wait, &wait, TASK_INTERRUPTIBLE); \
  while (!pico_stack_is_ready) \
    schedule(); \
  finish_wait(&picotcp_stack_init_wait, &wait);


#if defined STDSOCKET || defined __socklen_t_defined
#include "sys/types.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#define STDSOCKET
static inline int sockopt_get_name(int posix_name)
{
    switch (posix_name) {
        case IP_MULTICAST_LOOP: return PICO_IP_MULTICAST_LOOP;
        case IP_MULTICAST_TTL: return PICO_IP_MULTICAST_TTL;
        case IP_MULTICAST_IF: return PICO_IP_MULTICAST_IF;
        case IP_ADD_MEMBERSHIP: return PICO_IP_ADD_MEMBERSHIP;
        case IP_DROP_MEMBERSHIP: return PICO_IP_DROP_MEMBERSHIP;
        case SO_RCVBUF   : return PICO_SOCKET_OPT_RCVBUF;
        case SO_SNDBUF   : return PICO_SOCKET_OPT_SNDBUF;
    }
    return -1;
}


#else

typedef int socklen_t;
#ifndef __KERNEL__
#define AF_INET     (PICO_PROTO_IPV4)
#define AF_INET6    (PICO_PROTO_IPV6)
#define SOCK_STREAM  (PICO_PROTO_TCP)
#define SOCK_DGRAM   (PICO_PROTO_UDP)

#define SOL_SOCKET (0x80)

#define IP_MULTICAST_LOOP (PICO_IP_MULTICAST_LOOP)
#define IP_MULTICAST_TTL (PICO_IP_MULTICAST_TTL)
#define IP_MULTICAST_IF (PICO_IP_MULTICAST_IF)
#define IP_ADD_MEMBERSHIP (PICO_IP_ADD_MEMBERSHIP)
#define IP_DROP_MEMBERSHIP (PICO_IP_DROP_MEMBERSHIP)
#define SO_RCVBUF    (PICO_SOCKET_OPT_RCVBUF)
#define SO_SNDBUF    (PICO_SOCKET_OPT_SNDBUF)
#define sockopt_get_name(x) ((x))


struct sockaddr {
    uint16_t sa_family;
}; 

struct in_addr {
    uint32_t s_addr;
};

#define INADDR_ANY ((uint32_t)0U)

struct in6_addr {
    uint8_t s6_addr[16];
};

struct __attribute__((packed)) sockaddr_in {
    uint16_t sin_family;
    uint16_t sin_port;
    struct in_addr sin_addr;
    uint8_t _pad[SOCKSIZE - 8];         
};


struct __attribute__((packed)) sockaddr_in6 {
    uint16_t sin6_family;
    uint16_t sin6_port;
    uint32_t sin6_flowinfo;
    struct in6_addr sin6_addr;
    uint32_t sin6_scope_id;
};

struct __attribute__((packed)) sockaddr_storage {
    uint16_t ss_family;
    uint8_t  _pad[(SOCKSIZE6 - sizeof(uint16_t))];
};
#endif

/* getaddrinfo */
struct addrinfo {
    int              ai_flags;
    int              ai_family;
    int              ai_socktype;
    int              ai_protocol;
    socklen_t        ai_addrlen;
    struct sockaddr *ai_addr;
    char            *ai_canonname;
    struct addrinfo *ai_next;
};


/* hostent */
struct hostent {
    char  *h_name;            /* official name of host */
    char **h_aliases;         /* alias list */
    int    h_addrtype;        /* host address type */
    int    h_length;          /* length of address */
    char **h_addr_list;       /* list of addresses */
};
#define h_addr h_addr_list[0] /* for backward compatibility */

#endif /* __KERNEL__ */

#ifdef CONFIG_PICOTCP_DNS_CLIENT
struct hostent *pico_gethostbyname(const char *name);

/* getaddrinfo */
int pico_getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints,
                       struct addrinfo **res);

void pico_freeaddrinfo(struct addrinfo *res);
#endif


/* Non-POSIX */
void                         pico_bsd_init(void);
void                         pico_bsd_deinit(void);
void                         pico_bsd_stack_tick(void);

/*****************************************************************************
 * Public types/enumerations/variables
 ****************************************************************************/

/* Queue implementation API is: */

void * pico_mutex_init(void);
void pico_mutex_deinit(void * mutex);
void pico_mutex_lock(void * mutex);
int pico_mutex_lock_timeout(void * mutex, int timeout);
void pico_mutex_unlock(void * mutex);
void pico_mutex_unlock_ISR(void * mutex);

void * pico_signal_init(void);
void pico_signal_deinit(void * signal);
void pico_signal_wait(void * signal);
int pico_signal_wait_timeout(void * signal, int timeout);
void pico_signal_send(void * signal);
void pico_signal_send_ISR(void * signal);

/* ioctl.c */
int picotcp_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg);

/* af_inet.c */
int af_inet_picotcp_init(void);

#endif /* PICO_BSD_SOCKETS_H_ */
