/* Linux kernel osal implementation  */
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/tcp_states.h>

#include "picotcp.h"
#include "remcalls.h"
#include "doioctl.h"

/* debug config */

#define PICOTCP_DEBUG			0
#define PICOTCP_DEBUG_EVENTS	1
#define PICOTCP_DEBUG_POLL		0

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

struct mutex stack_mutex;

/* Sockets */
struct picotcp_sock {
	struct sock             sk; /* Must be the first member */
	struct rem_pico_socket *pico;
	uint8_t                 in_use;
	uint8_t                 state;
	uint16_t                events; /* events that we filter for */
	volatile uint16_t       revents; /* received events */
	volatile uint32_t       udpcnt;
	struct mutex            mutex_lock; /* mutex for clearing revents */
	struct net             *net; /* Network */
};

static inline struct picotcp_sock *picotcp_sock(struct socket *sock)
{
	return (struct picotcp_sock *)sock->sk;
}

int inline is_udp(struct picotcp_sock *psk)
{
	return psk->sk.sk_protocol == IPPROTO_UDP;
}

static inline void pico_stack_lock(void)
{
	mutex_lock(&stack_mutex);
	rem_stack_lock();
}

static inline void pico_stack_unlock(void)
{
	rem_stack_unlock();
	mutex_unlock(&stack_mutex);
}

static inline void psk_state_lock(struct picotcp_sock *sock)
{
	mutex_lock(&sock->mutex_lock);
}

static inline void psk_state_unlock(struct picotcp_sock *sock)
{
	mutex_unlock(&sock->mutex_lock);
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

/*** Helper functions ***/
static int bsd_to_pico_addr(union pico_address *addr, struct sockaddr *_saddr, socklen_t socklen)
{
	if (socklen == SOCKSIZE6) {
		struct sockaddr_in6 *saddr = (struct sockaddr_in6 *) _saddr;

		memcpy(&addr->ip6.addr, &saddr->sin6_addr.s6_addr, 16);
		saddr->sin6_family = AF_INET6;
	} else {
		struct sockaddr_in *saddr = (struct sockaddr_in *) _saddr;

		addr->ip4.addr = saddr->sin_addr.s_addr;
		saddr->sin_family = AF_INET;
		memset(saddr->sin_zero, 0, sizeof(saddr->sin_zero));
	}
	return 0;
}

static uint16_t bsd_to_pico_port(struct sockaddr *_saddr, socklen_t socklen)
{
	if (socklen == SOCKSIZE6) {
		struct sockaddr_in6 *saddr = (struct sockaddr_in6 *) _saddr;
		return saddr->sin6_port;
	} else {
		struct sockaddr_in *saddr = (struct sockaddr_in *) _saddr;
		return saddr->sin_port;
	}
}

static int pico_port_to_bsd(struct sockaddr *_saddr, socklen_t socklen, uint16_t port)
{
	if (socklen == SOCKSIZE6) {
		struct sockaddr_in6 *saddr = (struct sockaddr_in6 *) _saddr;
		saddr->sin6_port = port;
		return 0;
	} else {
		struct sockaddr_in *saddr = (struct sockaddr_in *) _saddr;
		saddr->sin_port = port;
		return 0;
	}
}

static int pico_addr_to_bsd(struct sockaddr *_saddr, socklen_t socklen, union pico_address *addr, uint16_t net)
{
	if (net == PICO_PROTO_IPV6) {
		struct sockaddr_in6 *saddr = (struct sockaddr_in6 *) _saddr;
		memcpy(&saddr->sin6_addr.s6_addr, &addr->ip6.addr, 16);
		saddr->sin6_family = AF_INET6;
		return 0;
	} else if (net == PICO_PROTO_IPV4) {
		struct sockaddr_in *saddr = (struct sockaddr_in *) _saddr;
		saddr->sin_addr.s_addr = addr->ip4.addr;
		saddr->sin_family = AF_INET;
		return 0;
	}
	printk(KERN_ERR "pico_addr_to_bsd: bad net=%d\n", net);
	return -1;
}

static struct proto picotcp_proto = {
	.name     = "PICOTCP",
	.owner    = THIS_MODULE,
	.obj_size = sizeof(struct picotcp_sock),
};

static uint16_t pico_bsd_select(struct picotcp_sock *psk)
{
	uint16_t events = psk->events & psk->revents; /* maybe an event we are waiting for, was already queued ? */
	DEFINE_WAIT(wait);

	picotcp_dbg("enter pico_bsd_select(%p,%lx)\n", psk, (unsigned long)psk->pico);

	/* wait for one of the selected events... */
	prepare_to_wait(sk_sleep(&psk->sk), &wait, TASK_INTERRUPTIBLE);
	while (!events) {
		events = (psk->revents & psk->events); /* filter for the events we were waiting for */
		if (!events)
			schedule();
		if (signal_pending(current)) {
			picotcp_dbg("set PICO_SOCK_EV_ERR\n");
			psk->revents = PICO_SOCK_EV_ERR;
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
	psk_state_lock(psk);

	psk->events = PICO_SOCK_EV_ERR;
	psk->events |= PICO_SOCK_EV_FIN;
	psk->events |= PICO_SOCK_EV_CONN;
	if (close)
		psk->events |= PICO_SOCK_EV_CLOSE;
	if (read)
		psk->events |= PICO_SOCK_EV_RD;
	if (write)
		psk->events |= PICO_SOCK_EV_WR;

	psk_state_unlock(psk);

	return pico_bsd_select(psk);
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

	psk_state_lock(psk);

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

	psk_state_unlock(psk);

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
	picotcp_dbg("event=%x\n", ev);
#endif

	if (!psk) {
		picotcp_dbg("endpoint not initialized yet!\n");
		/* endpoint not initialized yet! */
		return;
	}

	if (psk->sk.sk_err) {
		picotcp_dbg("psk->sk.sk_err\n");
		ev = PICO_SOCK_EV_ERR | (psk->sk.sk_err << 8);
	}

	if (!psk->in_use) {
		picotcp_dbg("!psk->in_use\n");
		return;
	}

	if (psk->pico != s) {
		picotcp_dbg("bad psk\n");
		return;
	}

	psk_state_lock(psk);

	psk->revents |= ev; /* set those events */

	if (ev & PICO_SOCK_EV_CONN) {
		if (psk->state != SOCK_LISTEN) {
			psk->state = SOCK_CONNECTED;
		}
	}

	if (ev & PICO_SOCK_EV_ERR) {
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

	psk_state_unlock(psk);

	/* sending the event, while no one was listening,
	   will just cause an extra loop in select() */
	wake_up_interruptible(sk_sleep(&psk->sk));

#if PICOTCP_DEBUG_EVENTS
	picotcp_dbg("leave picotcp_socket_event(%p,%lx)\n", priv, (unsigned long)s);
#endif
}

static void pico_event_clear(struct picotcp_sock *psk, uint16_t events)
{
	psk_state_lock(psk);
	psk->revents &= ~events;
	if (is_udp(psk) && (events & PICO_SOCK_EV_RD)) {
		if (psk->udpcnt)
			psk->udpcnt--;
		if (psk->udpcnt)
			psk->revents |= PICO_SOCK_EV_RD;
	}
	psk_state_unlock(psk);
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

	pico_stack_lock();
	//psk_state_lock(psk);
	err = rem_pico_socket_connect(psk->pico, &addr, port);
	//psk_state_unlock(psk);
	pico_stack_unlock();

	if (err) {
		picotcp_dbg("port=%d\n", port);
		picotcp_dbg("connect failed\n");
		ret = 0 - pico_err;
		goto quit;
	}

	if (is_udp(psk)) {
		picotcp_dbg("UDP: Connected\n");
		pico_event_clear(psk, PICO_SOCK_EV_CONN);
		ret = 0;
		goto quit;
	}

	if (flags & MSG_DONTWAIT) {
		picotcp_dbg("MSG_DONTWAIT\n");
		ret = -EWOULDBLOCK;
		goto quit;
	} else {
		/* wait for event */
		ev = pico_bsd_wait(psk, 0, 0, 0); /* wait for ERR, FIN and CONN */
	}

	if (ev & PICO_SOCK_EV_CONN) {
		/* clear the EV_CONN event */
		pico_event_clear(psk, PICO_SOCK_EV_CONN);
		ret = 0;
		goto quit;
	} else {
		pico_stack_lock();
		rem_pico_socket_close(psk->pico);
		psk->in_use = 0;
		pico_stack_unlock();
		ret = -EINTR;
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

	pico_stack_lock();
	if (rem_pico_socket_bind(psk->pico, &addr, &port) < 0) {
		pico_stack_unlock();
		picotcp_dbg("bind: failed\n");
		ret =  0 - pico_err;
		goto quit;
	}
	psk->state = SOCK_BOUND;
	pico_stack_unlock();

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

	pico_stack_lock();
	if (rem_pico_socket_getname(psk->pico, &addr, &port, &proto, peer) < 0) {
		pico_stack_unlock();
		ret = -EFAULT;
		goto quit;
	}
	pico_stack_unlock();

	if (proto == PICO_PROTO_IPV6)
		socklen = SOCKSIZE6;
	else
		socklen = SOCKSIZE;

	memset(local_addr, 0, socklen);

	if (pico_addr_to_bsd(local_addr, socklen, &addr, proto) < 0) {
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

static struct picotcp_sock *picotcp_sock_new(struct sock *parent, struct net *net, int protocol);

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

		pico_stack_lock();
		//psk_state_lock(psk);
		ps = rem_pico_socket_accept(psk->pico, &picoaddr, &port);
		//psk_state_unlock(psk);
		if (!ps) {
			pico_stack_unlock();
			ret = 0 - pico_err;
			goto quit;
		}
		pico_event_clear(psk, PICO_SOCK_EV_CONN); /* clear the CONN event the listening socket */
		picotcp_dbg("pico_socket accepted: %lx\n", (unsigned long)ps);
		newpsk = picotcp_sock_new(&psk->sk, psk->net, psk->sk.sk_protocol);
		if (!newpsk) {
			rem_pico_socket_close(ps);
			pico_stack_unlock();
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
		rem_set_priv(ps, newpsk);
		sock_graft(&newpsk->sk, newsock);
		pico_stack_unlock();
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

	pico_stack_lock();
	//psk_state_lock(psk);

	err = rem_pico_socket_listen(psk->pico, backlog);

	if (err) {
		ret = 0 - pico_err;
	} else {
		psk->state = SOCK_LISTEN;
		sk->sk_state = TCP_LISTEN;
	}
	//psk_state_unlock(psk);
	pico_stack_unlock();

	picotcp_dbg("leave picotcp_listen(%p, %lx), ret=%d\n", psk, (unsigned long)psk->pico, ret);

	return ret;
}

static int picotcp_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
{
	struct picotcp_sock *psk = picotcp_sock(sock);
	union pico_address   addr;
	uint16_t             port = 0;
	uint8_t             *kbuf = NULL;
	int                  tot_len = 0;
	int                  ret;


	picotcp_dbg("enter picotcp_sendmsg(%p, %lx), len=%ld\n", psk, (unsigned long)psk->pico, len);

	psk_sock_lock(psk);

	if (len <= 0) {
		ret = -EINVAL;
		goto quit;
	}

	if (is_udp(psk) && (len > 65535))
		len = 65535;

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
		pico_stack_lock();
		//psk_state_lock(psk);
		pico_event_clear(psk, PICO_SOCK_EV_WR);
		if (msg->msg_namelen > 0)
			r = rem_pico_socket_sendto(psk->pico, kbuf + tot_len, len - tot_len, &addr, port);
		else
			r = rem_pico_socket_send(psk->pico, kbuf + tot_len, len - tot_len);
		//psk_state_unlock(psk);
		pico_stack_unlock();
		if (r < 0) {
			ret = 0 - pico_err;
			goto quit;
		}

		tot_len += r;

		if ((tot_len > 0) && is_udp(psk))
			break;

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
				ret = -EINTR;
				goto quit;
			}
		}
	}

	ret = tot_len;

quit:

	if (kbuf)
		kfree(kbuf);

	psk_sock_unlock(psk);

	picotcp_dbg("leave picotcp_sendmsg(%p, %lx), ret=%d\n", psk, (unsigned long)psk->pico, ret);

	return ret;
}

static int picotcp_recvmsg(struct socket *sock, struct msghdr *msg, size_t len, int flags)
{
	struct picotcp_sock *psk = picotcp_sock(sock);
	int                  tot_len = 0;
	uint8_t             *kbuf = NULL;
	union pico_address   addr;
	uint16_t             port;
	int                  ret;

	picotcp_dbg("enter picotcp_recvmsg(%p, %lx) len=%ld flags=%x\n", psk, (unsigned long)psk->pico, len, flags);

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

	if (is_udp(psk) && (len > 65535))
		len = 65535;

	kbuf = kmalloc(len, GFP_KERNEL);
	if (!kbuf) {
		ret = -ENOMEM;
		goto quit;
	}

	while (tot_len < len) {
		int r;
		pico_stack_lock();
		//psk_state_lock(psk);
		r = rem_pico_socket_recvfrom(psk->pico, kbuf + tot_len, len - tot_len, &addr, &port);
		//psk_state_unlock(psk);
		pico_stack_unlock();
		if (r < 0) {
			picotcp_dbg("pico returned error %d\n", -pico_err);
			ret = 0 - pico_err;
			goto quit;
		}

		tot_len += r;

		if (r == 0 || is_udp(psk)) {
			pico_event_clear(psk, PICO_SOCK_EV_RD);
			pico_event_clear(psk, PICO_SOCK_EV_ERR);
			if (tot_len > 0)
				goto recv_success;
		}

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
				//adi: next read cleans it
				//pico_event_clear(psk, PICO_SOCK_EV_RD);
				pico_event_clear(psk, PICO_SOCK_EV_ERR);
				ret = -EINTR;
				goto quit;
			}
		}
	}

	recv_success:
	if (msg->msg_name) {
		picotcp_dbg("About to return from recvmsg. tot_len is %d\n", tot_len);
		pico_addr_to_bsd(msg->msg_name, msg->msg_namelen, &addr,
				PICO_PROTO_IPV4);
		pico_port_to_bsd(msg->msg_name, msg->msg_namelen, port);
		msg->msg_namelen = sizeof(struct sockaddr_in);
		picotcp_dbg(
				"Address is copied to msg(%p). msg->name is at %p, namelen is %d. Content: family=%04x - addr: %08x \n",
				msg, msg->msg_name, msg->msg_namelen,
				((struct sockaddr_in *) msg->msg_name)->sin_family,
				((struct sockaddr_in *) msg->msg_name)->sin_addr.s_addr);
	}

	if (memcpy_to_msg(msg, kbuf, tot_len) < 0) {
		picotcp_dbg("memcpy_to_msg_failed\n");
	}

	if (tot_len < len) {
		pico_event_clear(psk, PICO_SOCK_EV_RD);
		pico_event_clear(psk, PICO_SOCK_EV_ERR);
	}
	ret = tot_len;

quit:

	if (kbuf)
		kfree(kbuf);

	psk_sock_unlock(psk);

	picotcp_dbg("leave picotcp_recvmsg(%p, %lx), ret=%d\n", psk, (unsigned long)psk->pico, ret);

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
		pico_stack_lock();
		//psk_state_lock(psk);
		rem_pico_socket_shutdown(psk->pico, how);
		//psk_state_unlock(psk);
		pico_stack_unlock();
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

	pico_stack_lock();
	//psk_state_lock(psk);
	rem_set_priv(psk->pico, NULL);
	rem_pico_socket_close(psk->pico);
	psk->pico   = NULL;
	psk->in_use = 0;
	//psk_state_unlock(psk);
	pico_stack_unlock();
	mutex_destroy(&psk->mutex_lock);
	sock_orphan(sock->sk);

quit:

	picotcp_dbg("leave picotcp_release(%p, %lx), ret=%d\n", psk, (unsigned long)psk->pico, ret);

	return ret;
}

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
		ret = -EOPNOTSUPP;
		goto quit;
	}

	pico_stack_lock();
	ret = rem_pico_socket_getoption(psk->pico, option, val, &len);
	pico_stack_unlock();

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
		ret = 0;
		printk("picotcp: unknown option %d ignored\n", optname);
		//ret = -EOPNOTSUPP;
		goto quit;
	}

	if (copy_from_user(val, optval, optlen)) {
		ret = -EFAULT;
		goto quit;
	}

	pico_stack_lock();
	ret = rem_pico_socket_setoption(psk->pico, option, val, optlen);
	pico_stack_unlock();

quit:

	if (val)
		kfree(val);

	picotcp_dbg("leave picotcp_setsockopt(%p, %lx), ret=%d\n", psk, (unsigned long)psk->pico, ret);

	return ret;
}

const struct proto_ops picotcp_proto_ops = {
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
	.sendmsg    = picotcp_sendmsg,
	.recvmsg    = picotcp_recvmsg,
};
EXPORT_SYMBOL(picotcp_proto_ops);

static struct picotcp_sock *picotcp_sock_new(struct sock *parent, struct net *net, int protocol)
{
	struct picotcp_sock *psk = NULL;
	struct sock         *sk;

	//if (parent) bh_lock_sock(parent);

	sk = sk_alloc(net, PF_INET, GFP_ATOMIC, &picotcp_proto, 0);

	if (!sk)
		goto quit;

	sk->sk_protocol = protocol;

	psk = (struct picotcp_sock *) sk;
	mutex_init(&psk->mutex_lock);

	psk->state   = SOCK_OPEN;
	psk->net     = net;
	psk->in_use  = 0;
	psk->events  = 0;
	psk->revents = 0;
	psk->udpcnt  = 0;

quit:

	//if (parent) bh_unlock_sock(parent);

	return psk;
}

static int picotcp_create(struct net *net, struct socket *sock, int protocol, int kern)
{
	struct picotcp_sock    *psk= NULL;
	struct rem_pico_socket *ps = NULL;
	int                     ret;

	picotcp_dbg("enter picotcp_create()\n");

	sock->ops = &picotcp_proto_ops;

	picotcp_dbg("type = %d, protocol = %d\n", sock->type, protocol);

	/* Convert IP sockets into DGRAM, so ioctl are still possible (e.g.: ifconfig) */
	if (sock->type == SOCK_DGRAM)
		protocol = IPPROTO_UDP;
	else
		protocol = IPPROTO_TCP;

	pico_stack_lock();
	ps = rem_pico_socket_open(PICO_PROTO_IPV4, protocol);
	if (!ps) {
		ret = 0 - pico_err;
		goto quit;
	}

	psk = picotcp_sock_new(NULL, net, protocol);
	if (!psk) {
		rem_pico_socket_close(ps);
		ret = -ENOMEM;
		goto quit;
	}
	sock_init_data(sock, &psk->sk);
	psk->pico = ps;
	rem_set_priv(ps, psk);
	psk->in_use = 1;

	ret = 0;

quit:

	pico_stack_unlock();

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

	mutex_init(&stack_mutex);
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
	mutex_destroy(&stack_mutex);
}

MODULE_ALIAS_NETPROTO(PF_INET);
