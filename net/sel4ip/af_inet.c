/* Linux kernel osal implementation  */
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/tcp_states.h>

#include "picotcp.h"
#include "iprcchan.h"
#include "remcalls.h"
#include "doioctl.h"

/* debug config */

#define PICOTCP_DEBUG			0
#define PICOTCP_DEBUG_EVENTS	1
#define PICOTCP_DEBUG_POLL		1

#if PICOTCP_DEBUG
#define picotcp_dbg printk
#else
#define picotcp_dbg(...) /*as nothing*/
#endif

#define SOCK_OPEN                   0
#define SOCK_BOUND                  1
#define SOCK_LISTEN                 2
#define SOCK_CONNECTED              3
#define SOCK_ERROR                  4
#define SOCK_RESET_BY_PEER          5
#define SOCK_CLOSED                 100

struct mutex stack0_mutex;
struct mutex stack1_mutex;

/* Sockets */
struct picotcp_sock {
	struct sock             sk; /* Must be the first member */
	struct rem_pico_socket *pico;
	uint8_t                 in_use;
	uint8_t                 state;
	volatile uint16_t       revents; /* received events */
	volatile uint32_t       udpcnt;
	struct mutex            events_mutex; /* mutex for clearing revents */
	pico_err_t              everr; /* last error code from PICO_SOCK_EV_ERR */
	struct net             *net; /* Network */
	struct mutex           *stack_mutex; /* mutex for selected stack */
	iprcchan_t             *stack_chan; /* iprcchan for selected stack */
};

static inline struct picotcp_sock *picotcp_sock(struct socket *sock)
{
	return (struct picotcp_sock *)sock->sk;
}

int inline is_udp(struct picotcp_sock *psk)
{
	return psk->sk.sk_protocol == IPPROTO_UDP;
}

static inline void pico_stack_lock(struct mutex *mutex, iprcchan_t *chan)
{
	mutex_lock(mutex);
#ifndef MINLOCK
	rem_stack_lock(chan);
#endif
}

static inline void pico_stack_unlock(struct mutex *mutex, iprcchan_t *chan)
{
#ifndef MINLOCK
	rem_stack_unlock(chan);
#endif
	mutex_unlock(mutex);
}

static inline void pico_full_stack_lock(struct mutex *mutex, iprcchan_t *chan)
{
	pico_stack_lock(mutex, chan);
#ifdef MINLOCK
	rem_stack_lock(chan);
#endif
}

static inline void pico_full_stack_unlock(struct mutex *mutex, iprcchan_t *chan)
{
#ifdef MINLOCK
	rem_stack_unlock(chan);
#endif
	pico_stack_unlock(mutex, chan);
}

static inline void psk_stack_lock(struct picotcp_sock *sock)
{
	pico_stack_lock(sock->stack_mutex, sock->stack_chan);
}

static inline void psk_stack_unlock(struct picotcp_sock *sock)
{
	pico_stack_unlock(sock->stack_mutex, sock->stack_chan);
}

static inline void psk_full_stack_lock(struct picotcp_sock *sock)
{
	pico_full_stack_lock(sock->stack_mutex, sock->stack_chan);
}

static inline void psk_full_stack_unlock(struct picotcp_sock *sock)
{
	pico_full_stack_unlock(sock->stack_mutex, sock->stack_chan);
}

static inline void psk_events_lock(struct picotcp_sock *sock)
{
	mutex_lock(&sock->events_mutex);
}

static inline void psk_events_unlock(struct picotcp_sock *sock)
{
	mutex_unlock(&sock->events_mutex);
}

static inline void psk_sock_lock(struct picotcp_sock *sock)
{
	lock_sock((struct sock*)sock);
}

static inline void psk_sock_lock_nested(struct picotcp_sock *sock, int subclass)
{
	lock_sock_nested((struct sock*)sock, subclass);
}

static inline void psk_sock_unlock(struct picotcp_sock *sock)
{
	release_sock((struct sock*)sock);
}

/* UTILS */

static int err_from_ev(struct picotcp_sock *psk, uint16_t ev)
{
	if (ev & PICO_SOCK_EV_ERR) {
		picotcp_dbg("EV_ERR: %d\n", psk->everr);
		return psk->everr;
	}
	if (ev & PICO_SOCK_EV_FIN) {
		picotcp_dbg("EV_FIN\n");
		return ECONNRESET;
	}
	if (ev & PICO_SOCK_EV_CLOSE)
		picotcp_dbg("EV_CLOSE\n");
	else
		picotcp_dbg("EV_%d\n", ev);
	return EINTR;
}

/*** Helper functions ***/
static int bsd_to_pico_addr(union pico_address *addr, struct sockaddr *_saddr, socklen_t socklen)
{
	if (socklen == SOCKSIZE6) {
		struct sockaddr_in6 *saddr = (struct sockaddr_in6 *) _saddr;

		saddr->sin6_family = AF_INET6;
		memcpy(&addr->ip6.addr, &saddr->sin6_addr.s6_addr, 16);
		return 0;
	} else if (socklen == SOCKSIZE) {
		struct sockaddr_in *saddr = (struct sockaddr_in *) _saddr;

		saddr->sin_family = AF_INET;
		addr->ip4.addr = saddr->sin_addr.s_addr;
		return 0;
	}
	printk("bsd_to_pico_addr: bad socklen %d\n", socklen);
	return -1;
}

static uint16_t bsd_to_pico_port(struct sockaddr *_saddr, socklen_t socklen)
{
	if (socklen == SOCKSIZE6) {
		struct sockaddr_in6 *saddr = (struct sockaddr_in6 *) _saddr;
		return saddr->sin6_port;
	} else if (socklen == SOCKSIZE){
		struct sockaddr_in *saddr = (struct sockaddr_in *) _saddr;
		return saddr->sin_port;
	}
	printk("bsd_to_pico_port: bad socklen %d\n", socklen);
	return -1;
}

static int pico_port_to_bsd(struct sockaddr *_saddr, socklen_t socklen, uint16_t port)
{
	if (socklen == SOCKSIZE6) {
		struct sockaddr_in6 *saddr = (struct sockaddr_in6 *) _saddr;
		saddr->sin6_port = port;
		return 0;
	} else if (socklen == SOCKSIZE) {
		struct sockaddr_in *saddr = (struct sockaddr_in *) _saddr;
		saddr->sin_port = port;
		return 0;
	}
	printk(KERN_ERR "pico_port_to_bsd: bad socklen %d\n", socklen);
	return -1;
}

static int pico_addr_to_bsd(struct sockaddr *_saddr, socklen_t socklen, union pico_address *addr)
{
	if (socklen == SOCKSIZE6) {
		struct sockaddr_in6 *saddr = (struct sockaddr_in6 *) _saddr;
		memcpy(&saddr->sin6_addr.s6_addr, &addr->ip6.addr, 16);
		saddr->sin6_family = AF_INET6;
		return 0;
	} else if (socklen == SOCKSIZE) {
		struct sockaddr_in *saddr = (struct sockaddr_in *) _saddr;
		saddr->sin_addr.s_addr = addr->ip4.addr;
		saddr->sin_family = AF_INET;
		return 0;
	}
	printk(KERN_ERR "pico_addr_to_bsd: bad socklen %d\n", socklen);
	return -1;
}

static uint16_t pico_bsd_select(struct picotcp_sock *psk, uint16_t wait_events)
{
	uint16_t events = wait_events & psk->revents; /* maybe an event we are waiting for, was already queued ? */
	DEFINE_WAIT(wait);

	picotcp_dbg("enter pico_bsd_select(%p,%lx)\n", psk, (unsigned long)psk->pico);

	/* wait for one of the selected events... */
	prepare_to_wait(sk_sleep(&psk->sk), &wait, TASK_INTERRUPTIBLE);
	while (!events) {
		events = (psk->revents & wait_events); /* filter for the events we were waiting for */
		if (!events)
			schedule();
		if (signal_pending(current)) {
			picotcp_dbg("set PICO_SOCK_EV_ERR\n");
			psk->revents = PICO_SOCK_EV_ERR;
			psk->everr   = EINTR;
			break;
		}
	}
	finish_wait(sk_sleep(&psk->sk), &wait);
	/* the event we were waiting for happened, now report it */

	picotcp_dbg("leave pico_bsd_select(%p,%lx)\n", psk, (unsigned long)psk->pico);

	return events; /* return any event(s) that occurred, that we were waiting for */
}

static uint16_t pico_bsd_wait(struct picotcp_sock *psk, int read, int write, int close)
{
	uint16_t events;

	events = PICO_SOCK_EV_ERR | PICO_SOCK_EV_FIN | PICO_SOCK_EV_CONN;
	if (close)
		events |= PICO_SOCK_EV_CLOSE;
	if (read)
		events |= PICO_SOCK_EV_RD;
	if (write)
		events |= PICO_SOCK_EV_WR;

	return pico_bsd_select(psk, events);
}

static unsigned int picotcp_poll(struct file *file, struct socket *sock, poll_table *wait)
{
	struct picotcp_sock *psk = picotcp_sock(sock);
	struct sock         *sk = sock->sk;
	unsigned int         mask = 0;

#if PICOTCP_DEBUG_POLL
	picotcp_dbg("enter picotcp_poll(%p, %lx)\n", psk, (unsigned long)psk->pico);
#endif

	sock_poll_wait(file, sock, wait);

	psk_events_lock(psk);

	if (sk->sk_err)
		mask |= EPOLLERR;
	if (psk->revents & PICO_SOCK_EV_CLOSE)
		mask |= EPOLLHUP;
	if (psk->revents & PICO_SOCK_EV_FIN)
		mask |= EPOLLHUP;
	if (psk->revents & PICO_SOCK_EV_RD) {
		mask |= EPOLLIN | EPOLLRDNORM; // | EPOLLRDBAND;
	}
	if (psk->revents & PICO_SOCK_EV_CONN)
		mask |= EPOLLIN;
	if (psk->revents & PICO_SOCK_EV_WR)
		mask |= EPOLLOUT | EPOLLWRNORM; // | EPOLLWRBAND;

	/* Addendum: UDP can always write, by default... */
	if (is_udp(psk))
		mask |= EPOLLOUT | EPOLLWRNORM; // | EPOLLWRBAND;
	psk_events_unlock(psk);

#if PICOTCP_DEBUG_POLL
	picotcp_dbg("leave picotcp_poll(%p, %lx), mask=%x\n", psk, (unsigned long)psk->pico, mask);
#endif

	return mask;
}

static void picotcp_socket_event(uint16_t ev, void *s, void *priv)
{
	struct picotcp_sock *psk = priv;

#if PICOTCP_DEBUG_EVENTS
	picotcp_dbg("enter picotcp_socket_event(%p,%lx)\n", priv, (unsigned long)s);
	picotcp_dbg(KERN_CONT "event=%x ", ev);
	if (ev & PICO_SOCK_EV_CONN)
		picotcp_dbg(KERN_CONT " CONN");
	if (ev & PICO_SOCK_EV_ERR)
		picotcp_dbg(KERN_CONT " ERR");
	if (ev & PICO_SOCK_EV_CLOSE)
		picotcp_dbg(KERN_CONT " CLOSE");
	if (ev & PICO_SOCK_EV_FIN)
		picotcp_dbg(KERN_CONT " FIN");
	if (ev & PICO_SOCK_EV_RD)
		picotcp_dbg(KERN_CONT " RD");
	if (ev & PICO_SOCK_EV_WR)
		picotcp_dbg(KERN_CONT " WR");
	picotcp_dbg("");
#endif

	if (!psk) {
		picotcp_dbg("endpoint not initialized yet!\n");
		/* endpoint not initialized yet! */
		return;
	}

#if 0 // ???
	if (psk->sk.sk_err) {
		picotcp_dbg("psk->sk.sk_err\n");
		printk("sk_err\n");
		ev = PICO_SOCK_EV_ERR | (psk->sk.sk_err << 8);
	}
#endif

	if (!psk->in_use) {
		picotcp_dbg("!psk->in_use\n");
		printk("!in_use\n");
		return;
	}

	if (psk->pico != s) {
		picotcp_dbg("bad psk\n");
		printk("bad psk\n");
		return;
	}

	psk_events_lock(psk);

	psk->revents |= ev; /* set those events */

	if (ev & PICO_SOCK_EV_CONN) {
		if (psk->state != SOCK_LISTEN) {
			psk->state = SOCK_CONNECTED;
		}
	}

	if (ev & PICO_SOCK_EV_ERR) {
		// adi: ???
		printk("EV_ERR, pico_err=%d\n", pico_err);
		psk->everr = pico_err;
		if (pico_err == PICO_ERR_ECONNRESET) {
			dbg("Connection reset...\n");
			psk->state = SOCK_RESET_BY_PEER;
		}
	}

	if (ev & PICO_SOCK_EV_CLOSE) {
		psk->state = SOCK_CLOSED;
	}

	if (ev & PICO_SOCK_EV_FIN) {
		psk->state = SOCK_CLOSED;
	}

	if (is_udp(psk) && (ev & PICO_SOCK_EV_RD))
		psk->udpcnt++;

	psk_events_unlock(psk);

	/* sending the event, while no one was listening,
	   will just cause an extra loop in select() */
	wake_up_interruptible(sk_sleep(&psk->sk));

#if PICOTCP_DEBUG_EVENTS
	picotcp_dbg("leave picotcp_socket_event(%p,%lx)\n", priv, (unsigned long)s);
#endif
}

static void pico_event_clear(struct picotcp_sock *psk, uint16_t events)
{
	psk_events_lock(psk);
	psk->revents &= ~events;
	if (is_udp(psk) && (events & PICO_SOCK_EV_RD)) {
		if (psk->udpcnt)
			psk->udpcnt--;
		if (psk->udpcnt)
			psk->revents |= PICO_SOCK_EV_RD;
	}
	psk_events_unlock(psk);
}

static int picotcp_connect(struct socket *sock, struct sockaddr *_saddr, int socklen, int flags)
{
	struct picotcp_sock *psk = picotcp_sock(sock);
	union pico_address   addr;
	uint16_t             port;
	uint16_t             ev;
	int                  err;
	int                  ret;

	picotcp_dbg("enter connect(%p,%lx)\n", psk, (unsigned long)psk->pico);

	psk_sock_lock(psk);

	if (bsd_to_pico_addr(&addr, _saddr, socklen) < 0) {
		picotcp_dbg("Connect: invalid address\n");
		ret = -EINVAL;
		goto quit;
	}

	port = bsd_to_pico_port(_saddr, socklen);
	if (port == 0) {
		picotcp_dbg("Connect: invalid port\n");
		ret = -EINVAL;
		goto quit;
	}

	psk_stack_lock(psk);
	err = rem_pico_socket_connect(psk->stack_chan, psk->pico, &addr, port);
	psk_stack_unlock(psk);

	if (err) {
		picotcp_dbg("port=%d\n", port);
		picotcp_dbg("connect failed\n");
		ret = -pico_err;
		goto quit;
	}

	if (is_udp(psk)) {
		picotcp_dbg("UDP: Connected\n");
		pico_event_clear(psk, PICO_SOCK_EV_CONN);
		ret = 0;
		goto quit;
	}

	if (flags & MSG_DONTWAIT) {
		ret = -EWOULDBLOCK;
		goto quit;
	} else if (flags & O_NONBLOCK) {
		picotcp_dbg("O_NONBLOCK\n");
		ret = -EINPROGRESS;
		goto quit;
	} else {
		/* wait for event */
		ev = pico_bsd_wait(psk, 0, 0, 0); /* wait for ERR, FIN and CONN */
	}

	if (ev & PICO_SOCK_EV_CONN) {
		/* clear the EV_CONN event */
		pico_event_clear(psk, PICO_SOCK_EV_CONN);
		ret = 0;
	} else {
		ret = -err_from_ev(psk, ev);
	}

quit:

	psk_sock_unlock(psk);

	picotcp_dbg("leave picotcp_connect(%p, %lx), ret=%d\n", psk, (unsigned long)psk->pico, ret);

	return ret;
}

static int picotcp_bind(struct socket *sock, struct sockaddr *local_addr, int socklen)
{
	struct picotcp_sock *psk = picotcp_sock(sock);
	union pico_address   addr;
	uint16_t             port;
	int                  ret = 0;

	picotcp_dbg("enter picotcp_bind(%p, %lx)\n", psk, (unsigned long)psk->pico);

	psk_sock_lock(psk);

	if (bsd_to_pico_addr(&addr, local_addr, socklen) < 0) {
		picotcp_dbg("bind: invalid address\n");
		ret = -EINVAL;
		goto quit;
	}
	port = bsd_to_pico_port(local_addr, socklen);
	picotcp_dbg("bind to port %d\n", short_be(port));
	/* No check for port, if == 0 use autobind */

	psk_stack_lock(psk);
	if (rem_pico_socket_bind(psk->stack_chan, psk->pico, &addr, &port) < 0) {
		psk_stack_unlock(psk);
		picotcp_dbg("bind: failed\n");
		ret =  -pico_err;
		goto quit;
	}
	psk->state = SOCK_BOUND;
	psk_stack_unlock(psk);

	pico_port_to_bsd(local_addr, socklen, port);

quit:

	psk_sock_unlock(psk);

	picotcp_dbg("leave picotcp_bind(%p, %lx), ret=%d\n", psk, (unsigned long)psk->pico, ret);

	return ret;
}

static int picotcp_getname(struct socket *sock, struct sockaddr *local_addr, int peer)
{
	struct picotcp_sock *psk = picotcp_sock(sock);
	union pico_address   addr;
	uint16_t             port, proto;
	int                  socklen;
	int                  ret;

	picotcp_dbg("enter picotcp_getname(%p, %lx, %d)\n", psk, (unsigned long)psk->pico, peer);

	psk_sock_lock(psk);

	psk_stack_lock(psk);
	if (rem_pico_socket_getname(psk->stack_chan, psk->pico, &addr, &port, &proto, peer) < 0) {
		psk_stack_unlock(psk);
		ret = -EFAULT;
		goto quit;
	}
	psk_stack_unlock(psk);

	if (proto == PICO_PROTO_IPV6)
		socklen = SOCKSIZE6;
	else
		socklen = SOCKSIZE;

	memset(local_addr, 0, socklen);

	if (pico_addr_to_bsd(local_addr, socklen, &addr) < 0) {
		ret = -EINVAL;
		goto quit;
	}

	pico_port_to_bsd(local_addr, socklen, port);
	ret = socklen;

quit:

	psk_sock_unlock(psk);

	picotcp_dbg("leave picotcp_getname(%p, %lx), ret=%d\n", psk, (unsigned long)psk->pico, ret);

	return ret;
}

static struct picotcp_sock *picotcp_sock_new(struct sock  *parent,
		                                     struct net   *net,
											 int           protocol,
											 struct mutex *stack_mutex,
											 iprcchan_t   *stack_chan);

static int picotcp_accept(struct socket *sock, struct socket *newsock, int flags, bool kern)
{
	struct picotcp_sock *psk = picotcp_sock(sock);
	struct picotcp_sock *newpsk;
	uint16_t             events;
	union pico_address   picoaddr;
	uint16_t             port;
	int                  ret;

	picotcp_dbg("enter picotcp_accept(%p, %lx)\n", psk, (unsigned long)psk->pico);

	psk_sock_lock_nested(psk, SINGLE_DEPTH_NESTING);

	if (psk->state != SOCK_LISTEN) {
		picotcp_dbg("invalid socket state, not listening\n");
		ret = -EOPNOTSUPP;
		goto quit;
	}

	if (flags & O_NONBLOCK && 0) {
		picotcp_dbg("O_NONBLOCK\n");
		events = PICO_SOCK_EV_CONN;
	} else {
		picotcp_dbg("wait...\n");
		events = pico_bsd_wait(psk, 0, 0, 0);
		picotcp_dbg("done.\n");
	}


	/* Here I check for psk again, to avoid races */
	if (!psk || !psk->in_use) {
		ret = -EINTR;
		goto quit;
	}

	if (events & PICO_SOCK_EV_CONN) {
		struct rem_pico_socket *ps;

		psk_full_stack_lock(psk);

		ps = rem_pico_socket_accept(psk->stack_chan, psk->pico, &picoaddr, &port);
		if (!ps) {
			psk_stack_unlock(psk);
			ret = -pico_err;
			goto quit;
		}
		pico_event_clear(psk, PICO_SOCK_EV_CONN); /* clear the CONN event the listening socket */
		picotcp_dbg("pico_socket accepted: %lx\n", (unsigned long)ps);
		newpsk = picotcp_sock_new(&psk->sk, psk->net, psk->sk.sk_protocol, psk->stack_mutex, psk->stack_chan);
		if (!newpsk) {
			rem_pico_socket_close(psk->stack_chan, ps);

			psk_full_stack_unlock(psk);

			ret = -ENOMEM;
			goto quit;
		}
		//sock_init_data(newsock, &newpsk->sk);
		//newsock->sk = &newpsk->sk;
		newsock->state = SS_CONNECTED;
		newpsk->state  = SOCK_CONNECTED;
		newpsk->sk.sk_state = TCP_ESTABLISHED;
		newpsk->pico   = ps;
		newpsk->in_use = 1;
		rem_set_priv(newpsk->stack_chan, ps, newpsk);
		sock_graft(&newpsk->sk, newsock);

		psk_full_stack_unlock(psk);

		ret = 0;
	} else {
		ret = -EAGAIN;
	}

quit:

	psk_sock_unlock(psk);

	picotcp_dbg("leave picotcp_accept(%p, %lx), ret=%d\n", psk, (unsigned long)psk->pico, ret);

	return ret;
}

static int picotcp_listen(struct socket *sock, int backlog)
{
	struct picotcp_sock *psk = picotcp_sock(sock);
	struct sock         *sk = sock->sk;
	int                  err;
	int                  ret = 0;

	picotcp_dbg("enter picotcp_listen(%p, %lx)\n", psk, (unsigned long)psk->pico);

	psk_stack_lock(psk);

	err = rem_pico_socket_listen(psk->stack_chan, psk->pico, backlog);
	if (err) {
		ret = -pico_err;
	} else {
		psk->state = SOCK_LISTEN;
		sk->sk_state = TCP_LISTEN;
	}

	psk_stack_unlock(psk);

	picotcp_dbg("leave picotcp_listen(%p, %lx), ret=%d\n", psk, (unsigned long)psk->pico, ret);

	return ret;
}

static int picotcp_sendmsg_stream(struct socket *sock, struct msghdr *msg, size_t len)
{
	struct picotcp_sock *psk = picotcp_sock(sock);
	union pico_address   addr;
	uint16_t             port = 0;
	uint8_t             *kbuf = NULL;
	int                  tot_len = 0;
	int                  ret;


	picotcp_dbg("enter picotcp_sendmsg_stream(%p, %lx), len=%ld\n", psk, (unsigned long)psk->pico, len);

	psk_sock_lock(psk);

	if (len <= 0) {
		ret = -EINVAL;
		goto quit;
	}

	kbuf = kmalloc(len, GFP_KERNEL);
	if (!kbuf) {
		ret = -ENOMEM;
		goto quit;
	}

	if (msg->msg_namelen > 0) {
		bsd_to_pico_addr(&addr, msg->msg_name, msg->msg_namelen);
		port = bsd_to_pico_port(msg->msg_name, msg->msg_namelen);
	}

	if (memcpy_from_msg(kbuf, msg, len) < 0) {
		picotcp_dbg("memcpy_from_msg() failed\n");
	}

	while (tot_len < len) {
		int r;

		psk_stack_lock(psk);

		pico_event_clear(psk, PICO_SOCK_EV_WR);
		if (msg->msg_namelen > 0)
			r = rem_pico_socket_sendto(psk->stack_chan, psk->pico, kbuf + tot_len, len - tot_len, &addr, port);
		else
			r = rem_pico_socket_send(psk->stack_chan, psk->pico, kbuf + tot_len, len - tot_len);

		psk_stack_unlock(psk);

		if (r < 0) {
			ret = -pico_err;
			goto quit;
		}

		tot_len += r;

		if (msg->msg_flags & MSG_DONTWAIT) {
			if (tot_len > 0)
				break;
			else {
				ret = -EWOULDBLOCK;
				goto quit;
			}
		}

		if (tot_len < len) {
			uint16_t ev = pico_bsd_wait(psk, 0, 1, 1);
			if ((ev & (PICO_SOCK_EV_ERR | PICO_SOCK_EV_FIN | PICO_SOCK_EV_CLOSE)) || (ev == 0)) {
				pico_event_clear(psk, PICO_SOCK_EV_WR);
				pico_event_clear(psk, PICO_SOCK_EV_ERR);
				ret = -err_from_ev(psk, ev);
				goto quit;
			}
		}
	}

	ret = tot_len;

quit:

	if (kbuf)
		kfree(kbuf);

	psk_sock_unlock(psk);

	picotcp_dbg("leave picotcp_sendmsg_stream(%p, %lx), ret=%d\n", psk, (unsigned long)psk->pico, ret);

	return ret;
}

static int picotcp_recvmsg_stream(struct socket *sock, struct msghdr *msg, size_t len, int flags)
{
	struct picotcp_sock *psk = picotcp_sock(sock);
	int                  tot_len = 0;
	uint8_t             *kbuf = NULL;
	union pico_address   addr;
	uint16_t             port;
	int                  ret;

	picotcp_dbg("enter picotcp_recvmsg_stream(%p, %lx) len=%ld flags=%x\n", psk, (unsigned long)psk->pico, len, flags);

	psk_sock_lock(psk);

	if (len < 1) {
		ret = -EINVAL;
		goto quit;
	}

	if (flags & MSG_PEEK) {
		printk(KERN_ERR "MSG_PEEK not supported\n");
		ret = -EOPNOTSUPP;
		goto quit;
	}

	if (flags & MSG_ERRQUEUE) {
		printk("picotcp: MSG_ERRQUE not supported, return 0\n");
		ret = 0;
		goto quit;
	}

	kbuf = kmalloc(len, GFP_KERNEL);
	if (!kbuf) {
		ret = -ENOMEM;
		goto quit;
	}

	while (tot_len < len) {
		int r, more;

		psk_full_stack_lock(psk);

		r = rem_pico_socket_recvfrom2(psk->stack_chan, psk->pico, kbuf + tot_len, len - tot_len, &addr, &port, false, &more);
		if (!more) {
			pico_event_clear(psk, PICO_SOCK_EV_RD);
			pico_event_clear(psk, PICO_SOCK_EV_ERR);
		}

		psk_full_stack_unlock(psk);

		if (r < 0) {
			picotcp_dbg("pico returned error %d\n", -pico_err);
			ret = -pico_err;
			goto quit;
		}

		tot_len += r;

		if ((r == 0) && (tot_len > 0))
			goto recv_success;

		if (flags & MSG_DONTWAIT) {
			if (tot_len > 0)
				goto recv_success;
			else {
				ret = -EWOULDBLOCK;
				goto quit;
			}
		}

		if (tot_len < len) {
			uint16_t ev = pico_bsd_wait(psk, 1, 0, 1);
			if ((ev & (PICO_SOCK_EV_ERR | PICO_SOCK_EV_FIN | PICO_SOCK_EV_CLOSE)) || (ev == 0)) {
				pico_event_clear(psk, PICO_SOCK_EV_RD);
				pico_event_clear(psk, PICO_SOCK_EV_ERR);
				ret = -err_from_ev(psk, ev);
				goto quit;
			}
		}
	}

	recv_success:
	if (msg->msg_name) {
		picotcp_dbg("About to return from recvmsg. tot_len is %d\n", tot_len);
		msg->msg_namelen = sizeof(struct sockaddr_in);
		pico_addr_to_bsd(msg->msg_name, msg->msg_namelen, &addr);
		pico_port_to_bsd(msg->msg_name, msg->msg_namelen, port);
		picotcp_dbg(
				"Address is copied to msg(%p). msg->name is at %p, namelen is %d. Content: family=%04x - addr: %08x \n",
				msg, msg->msg_name, msg->msg_namelen,
				((struct sockaddr_in *) msg->msg_name)->sin_family,
				((struct sockaddr_in *) msg->msg_name)->sin_addr.s_addr);
	}

	if (memcpy_to_msg(msg, kbuf, tot_len) < 0) {
		picotcp_dbg("memcpy_to_msg_failed\n");
	}

	ret = tot_len;

quit:

	if (kbuf)
		kfree(kbuf);

	psk_sock_unlock(psk);

	picotcp_dbg("leave picotcp_recvmsg_stream(%p, %lx), ret=%d\n", psk, (unsigned long)psk->pico, ret);

	return ret;
}

static int picotcp_sendmsg_dgram(struct socket *sock, struct msghdr *msg, size_t len)
{
	struct picotcp_sock *psk = picotcp_sock(sock);
	union pico_address   addr;
	uint16_t             port = 0;
	int                  ret;


	picotcp_dbg("enter picotcp_sendmsg_dgram(%p, %lx), len=%ld\n", psk, (unsigned long)psk->pico, len);

	psk_sock_lock(psk);

	if (len <= 0) {
		ret = -EINVAL;
		goto quit;
	}

	if (len > REM_BUFFSIZE)
		len = REM_BUFFSIZE;

	psk_stack_lock(psk);

	if (msg->msg_namelen > 0) {
		bsd_to_pico_addr(&addr, msg->msg_name, msg->msg_namelen);
		port = bsd_to_pico_port(msg->msg_name, msg->msg_namelen);
		ret = rem_pico_socket_sendto_msg(psk->stack_chan, psk->pico, msg, len, &addr, port);
	} else {
		ret = rem_pico_socket_send_msg(psk->stack_chan, psk->pico, msg, len );
	}

	psk_stack_unlock(psk);

	if (ret < 0) {
		ret = -pico_err;
		goto quit;
	}

quit:

	psk_sock_unlock(psk);

	picotcp_dbg("leave picotcp_sendmsg_dgram(%p, %lx), ret=%d\n", psk, (unsigned long)psk->pico, ret);

	return ret;
}

static int picotcp_recvmsg_dgram(struct socket *sock, struct msghdr *msg, size_t len, int flags)
{
	struct picotcp_sock *psk = picotcp_sock(sock);
	union pico_address   addr;
	uint16_t             port;
	int                  ret;

	picotcp_dbg("enter picotcp_recvmsg_stream(%p, %lx) len=%ld flags=%x\n", psk, (unsigned long)psk->pico, len, flags);

	psk_sock_lock(psk);

	if (len < 1) {
		ret = -EINVAL;
		goto quit;
	}

	if (flags & MSG_PEEK) {
		printk(KERN_ERR "MSG_PEEK not supported\n");
		ret = -EOPNOTSUPP;
		goto quit;
	}

	if (flags & MSG_ERRQUEUE) {
		printk("picotcp: MSG_ERRQUE not supported, return 0\n");
		ret = 0;
		goto quit;
	}

	if (len > REM_BUFFSIZE)
		len = REM_BUFFSIZE;

	while (true) {
		uint16_t ev;

		psk_stack_lock(psk);

		ret = rem_pico_socket_recvfrom_msg(psk->stack_chan, psk->pico, msg, len,
				&addr, &port);

		psk_stack_unlock(psk);

		if (ret < 0) {
			picotcp_dbg("pico returned error %d\n", -pico_err);
			ret = -pico_err;
			goto quit;
		}

		pico_event_clear(psk, PICO_SOCK_EV_RD);
		pico_event_clear(psk, PICO_SOCK_EV_ERR);

		if (ret)
			break;

		if (flags & MSG_DONTWAIT) {
			ret = -EWOULDBLOCK;
			goto quit;
		}

		ev = pico_bsd_wait(psk, 1, 0, 1);
		if ((ev & (PICO_SOCK_EV_ERR | PICO_SOCK_EV_FIN | PICO_SOCK_EV_CLOSE))
				|| (ev == 0)) {
			pico_event_clear(psk, PICO_SOCK_EV_RD);
			pico_event_clear(psk, PICO_SOCK_EV_ERR);
			ret = -err_from_ev(psk, ev);
			goto quit;
		}
	}

	if (msg->msg_name) {
		picotcp_dbg("About to return from recvmsg. tot_len is %d\n", ret);
		msg->msg_namelen = sizeof(struct sockaddr_in);
		pico_addr_to_bsd(msg->msg_name, msg->msg_namelen, &addr);
		pico_port_to_bsd(msg->msg_name, msg->msg_namelen, port);
		picotcp_dbg(
				"Address is copied to msg(%p). msg->name is at %p, namelen is %d. Content: family=%04x - addr: %08x \n",
				msg, msg->msg_name, msg->msg_namelen,
				((struct sockaddr_in *) msg->msg_name)->sin_family,
				((struct sockaddr_in *) msg->msg_name)->sin_addr.s_addr);
	}

quit:

	psk_sock_unlock(psk);

	picotcp_dbg("leave picotcp_recvmsg_dgram(%p, %lx), ret=%d\n", psk, (unsigned long)psk->pico, ret);

	return ret;
}

static int picotcp_shutdown(struct socket *sock, int how)
{
	struct picotcp_sock *psk = picotcp_sock(sock);
	int                  ret = 0;

	picotcp_dbg("enter picotcp_shutdown(%p, %lx)\n", psk, (unsigned long)psk->pico);

	how++; /* ... see ipv4/af_inet.c */

	if (psk->pico) /* valid socket, try to close it */
	{
		psk_stack_lock(psk);

		rem_pico_socket_shutdown(psk->stack_chan, psk->pico, how);

		psk_stack_unlock(psk);
	}

	picotcp_dbg("leave picotcp_shutdown(%p, %lx)\n", psk, (unsigned long)psk->pico);

	return ret;
}

static int picotcp_release(struct socket *sock)
{
	struct picotcp_sock *psk = picotcp_sock(sock);
	int                  ret = 0;

	picotcp_dbg("enter picotcp_release(%p, %lx)\n", psk, (unsigned long)psk->pico);

	if (!psk) {
		ret = -EINVAL;
		goto quit;
	}

	psk_full_stack_lock(psk);

	rem_set_priv(psk->stack_chan, psk->pico, NULL);
	rem_pico_socket_close(psk->stack_chan, psk->pico);
	psk->pico   = NULL;
	psk->in_use = 0;

	psk_full_stack_unlock(psk);

	mutex_destroy(&psk->events_mutex);
	sock_orphan(sock->sk);

quit:

	picotcp_dbg("leave picotcp_release(%p, %lx), ret=%d\n", psk, (unsigned long)psk->pico, ret);

	return ret;
}

#define OPT_IGNORE	-2

static int optget(int lvl, int optname)
{
	int option = -1;

	if (lvl == SOL_SOCKET) {
		switch (optname) {
		case SO_SNDBUF:
			option = PICO_SOCKET_OPT_SNDBUF;
			break;
		case SO_RCVBUF:
			option = PICO_SOCKET_OPT_RCVBUF;
			break;
		}
	} else if (lvl == IPPROTO_IP) {
		switch (optname) {
		case IP_MULTICAST_IF:
			option = PICO_IP_MULTICAST_IF;
			break;
		case IP_MULTICAST_TTL:
			option = PICO_IP_MULTICAST_TTL;
			break;
		case IP_MULTICAST_LOOP:
			option = PICO_IP_MULTICAST_LOOP;
			break;
		case IP_ADD_MEMBERSHIP:
			option = PICO_IP_ADD_MEMBERSHIP;
			break;
		case IP_DROP_MEMBERSHIP:
			option = PICO_IP_DROP_MEMBERSHIP;
			break;

		// these are ignored silently

		case IP_PKTINFO:
		case IP_RECVERR:
		case IP_FREEBIND:
		case IP_TOS:
		case IP_OPTIONS:
			return OPT_IGNORE;

		}
	} else if (lvl == IPPROTO_TCP) {
		if (optname == TCP_NODELAY)
			option = PICO_TCP_NODELAY;
	}
	return option;
}

static int picotcp_getsockopt(struct socket *sock, int level, int optname, char __user *optval, int __user *optlen)
{
	struct picotcp_sock *psk = picotcp_sock(sock);
	int                  option = optget(level, optname);
	int                  len;
	uint8_t             *val;
	int                  ret = 0;

	picotcp_dbg("enter picotcp_getsockopt(%p, %lx)\n", psk, (unsigned long)psk->pico);

	if (copy_from_user(&len, optlen, sizeof(int)) > 0) {
		ret = -EFAULT;
		goto quit;
	}

	val = kmalloc(len, GFP_KERNEL);

	if (!val) {
		ret = -ENOMEM;
		goto quit;
	}

	if (option < 0) {
		if (option == OPT_IGNORE)
			picotcp_dbg("picotcp_getsockopt(): unknown level %d, optname %d ignored\n", level, optname);
		else
			printk("picotcp_getsockopt(): unknown level %d, optname %d ignored\n", level, optname);
		ret = -EOPNOTSUPP;
		goto quit;
	}

	psk_stack_lock(psk);
	ret = rem_pico_socket_getoption(psk->stack_chan, psk->pico, option, val, &len);
	psk_stack_unlock(psk);

	if (copy_to_user(optlen, &len, sizeof(int)) > 0) {
		ret = -EFAULT;
		goto quit;
	}

	if (copy_to_user(optval, val, len) > 0) {
		ret = -EFAULT;
		goto quit;
	}

quit:

	if (val)
		kfree(val);

	picotcp_dbg("leave picotcp_getsockopt(%p, %lx), ret=%d\n", psk, (unsigned long)psk->pico, ret);

	return ret;
}

static int picotcp_setsockopt(struct socket *sock, int level, int optname, char __user *optval, unsigned int optlen)
{
	struct picotcp_sock *psk = picotcp_sock(sock);
	int                  option = optget(level, optname);
	uint8_t             *val = kmalloc(optlen, GFP_KERNEL);
	int                  ret = 0;

	picotcp_dbg("enter picotcp_setsockopt(%p, %lx)\n", psk, (unsigned long)psk->pico);

	if (!val) {
		ret = -ENOMEM;
		goto quit;
	}

	if (option < 0) {
		if (option == OPT_IGNORE)
			picotcp_dbg("picotcp_setsockopt(): unknown level %d, optname %d ignored\n", level, optname);
		else
			printk("picotcp_setsockopt(): unknown level %d, optname %d ignored\n", level, optname);
		ret = 0;
		goto quit;
	}

	if (copy_from_user(val, optval, optlen)) {
		ret = -EFAULT;
		goto quit;
	}

	psk_stack_lock(psk);
	ret = rem_pico_socket_setoption(psk->stack_chan, psk->pico, option, val, optlen);
	psk_stack_unlock(psk);

quit:

	if (val)
		kfree(val);

	picotcp_dbg("leave picotcp_setsockopt(%p, %lx), ret=%d\n", psk, (unsigned long)psk->pico, ret);

	return ret;
}

static struct proto picotcp_proto = {
	.name     = "PICOTCP",
	.owner    = THIS_MODULE,
	.obj_size = sizeof(struct picotcp_sock),
};

const struct proto_ops picotcp_proto_ops_stream = {
	.family     = PF_INET,
	.owner      = THIS_MODULE,
	.release    = picotcp_release,
	.ioctl      = doioctl,
	.connect    = picotcp_connect,
	.bind       = picotcp_bind,
	.listen     = picotcp_listen,
	.getname    = picotcp_getname,
	.accept     = picotcp_accept,
	.shutdown   = picotcp_shutdown,
	.poll       = picotcp_poll,
	.mmap       = sock_no_mmap,
	.socketpair = sock_no_socketpair,
	.setsockopt = picotcp_setsockopt,
	.getsockopt = picotcp_getsockopt,
	.sendmsg    = picotcp_sendmsg_stream,
	.recvmsg    = picotcp_recvmsg_stream,
};
EXPORT_SYMBOL(picotcp_proto_ops_stream);

const struct proto_ops picotcp_proto_ops_dgram = {
	.family     = PF_INET,
	.owner      = THIS_MODULE,
	.release    = picotcp_release,
	.ioctl      = doioctl,
	.connect    = picotcp_connect,
	.bind       = picotcp_bind,
	.listen     = picotcp_listen,
	.getname    = picotcp_getname,
	.accept     = sock_no_accept,
	.shutdown   = picotcp_shutdown,
	.poll       = picotcp_poll,
	.mmap       = sock_no_mmap,
	.socketpair = sock_no_socketpair,
	.setsockopt = picotcp_setsockopt,
	.getsockopt = picotcp_getsockopt,
	.sendmsg    = picotcp_sendmsg_dgram,
	.recvmsg    = picotcp_recvmsg_dgram,
};
EXPORT_SYMBOL(picotcp_proto_ops_dgram);

static struct picotcp_sock *picotcp_sock_new(struct sock  *parent,
		                                     struct net   *net,
											 int           protocol,
											 struct mutex *stack_mutex,
											 iprcchan_t   *stack_chan)
{
	struct picotcp_sock *psk = NULL;
	struct sock         *sk;

	//if (parent) bh_lock_sock(parent);

	sk = sk_alloc(net, PF_INET, GFP_ATOMIC, &picotcp_proto, 0);

	if (!sk)
		goto quit;

	sk->sk_protocol = protocol;

	psk = (struct picotcp_sock *) sk;
	mutex_init(&psk->events_mutex);

	psk->state       = SOCK_OPEN;
	psk->net         = net;
	psk->in_use      = 0;
	psk->revents     = 0;
	psk->udpcnt      = 0;
	psk->stack_mutex = stack_mutex;
	psk->stack_chan  = stack_chan;

quit:

	//if (parent) bh_unlock_sock(parent);

	return psk;
}

static int picotcp_create(struct net *net, struct socket *sock, int protocol, int kern)
{
	struct picotcp_sock    *psk= NULL;
	struct rem_pico_socket *ps = NULL;
	int                     ret;
	struct mutex           *stack_mutex;
	iprcchan_t             *stack_chan;

	picotcp_dbg("enter picotcp_create()\n");

	picotcp_dbg("type = %d, protocol = %d\n", sock->type, protocol);

	if (protocol & (1<<15)) {
		stack_mutex = &stack1_mutex;
		stack_chan  = rem_get_chan(1);
	} else {
		stack_mutex = &stack0_mutex;
		stack_chan  = rem_get_chan(0);
	}

	/* Convert IP sockets into DGRAM, so ioctl are still possible (e.g.: ifconfig) */
	if (sock->type == SOCK_DGRAM) {
		protocol = IPPROTO_UDP;
		sock->ops = &picotcp_proto_ops_dgram;
	} else {
		protocol = IPPROTO_TCP;
		sock->ops = &picotcp_proto_ops_stream;
	}

	pico_full_stack_lock(stack_mutex, stack_chan);

	ps = rem_pico_socket_open(stack_chan, PICO_PROTO_IPV4, protocol);
	if (!ps) {
		ret = -pico_err;
		goto quit;
	}

	psk = picotcp_sock_new(NULL, net, protocol, stack_mutex, stack_chan);
	if (!psk) {
		rem_pico_socket_close(stack_chan, ps);
		ret = -ENOMEM;
		goto quit;
	}
	sock_init_data(sock, &psk->sk);
	psk->pico = ps;
	rem_set_priv(stack_chan, ps, psk);
	psk->in_use = 1;

	ret = 0;

quit:

	pico_full_stack_unlock(stack_mutex, stack_chan);

	picotcp_dbg("leave picotcp_create(%p, %lx), ret=%d\n", psk, (unsigned long)ps, ret);

	return ret;
}

static int __net_init picotcp_net_init(struct net *net)
{
	return 0;
}

static void __net_exit picotcp_net_exit(struct net *net)
{
}

static const struct net_proto_family picotcp_family_ops = {
	.family = PF_INET,
	.create = picotcp_create,
	.owner  = THIS_MODULE,
};

static struct pernet_operations picotcp_net_ops = {
	.init = picotcp_net_init,
	.exit = picotcp_net_exit,
};

int af_inet_picotcp_init(void)
{
	int rc;

	mutex_init(&stack0_mutex);
	mutex_init(&stack1_mutex);
	rc = rem_init(picotcp_socket_event);
	if (rc)
		panic("Cannot initialize remote functions\n");
	rc = proto_register(&picotcp_proto, 1);
	if (rc) {
		rem_deinit();
		panic("Cannot register AF_INET family for PicoTCP\n");
	}
	sock_register(&picotcp_family_ops);
	register_pernet_subsys(&picotcp_net_ops);
	return 0;
}

static void __exit af_inet_picotcp_exit(void) {
	sock_unregister(PF_INET);
	proto_unregister(&picotcp_proto);
	unregister_pernet_subsys(&picotcp_net_ops);
	rem_deinit();
	mutex_destroy(&stack0_mutex);
	mutex_destroy(&stack1_mutex);
}

MODULE_ALIAS_NETPROTO(PF_INET);
