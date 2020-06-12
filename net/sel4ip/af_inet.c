/* Linux kernel osal implementation  */
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/tcp_states.h>

#include "picotcp.h"
#include "remcalls.h"
#include "doioctl.h"

#define SOCK_OPEN                   0
#define SOCK_BOUND                  1
#define SOCK_LISTEN                 2
#define SOCK_CONNECTED              3
#define SOCK_ERROR                  4
#define SOCK_RESET_BY_PEER          5
#define SOCK_CLOSED                 100

//#define picotcp_dbg(...) /*do{}while(0)*/
#define picotcp_dbg printk

/* UTILS */
void * pico_mutex_init(void)
{
	struct mutex *m = kmalloc(sizeof(struct mutex), GFP_ATOMIC);

	if (!m)
		return NULL;
	mutex_init(m);
	if (!m)
		return NULL;
	return m;
}

void pico_mutex_deinit(void *_m)
{
	struct mutex *m = (struct mutex *) _m;

	mutex_destroy(m);
	kfree(m);
}

void pico_mutex_lock(void *_m)
{
	struct mutex *m = (struct mutex *) _m;

	mutex_lock(m);
}

void pico_mutex_unlock(void *_m)
{
	struct mutex *m = (struct mutex *) _m;

	mutex_unlock(m);
}

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
		picotcp_dbg("Found IPv4, port is %hu\n", short_be(saddr->sin_port));
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
	pico_err = PICO_ERR_EINVAL;
	return -1;
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
	return -1;

}

/* Sockets */
struct picotcp_sock {
	struct sock             sk; /* Must be the first member */
	struct rem_pico_socket *pico;
	uint16_t                pico_tproto;
	uint8_t                 in_use;
	uint8_t                 state;
	uint16_t                events; /* events that we filter for */
	volatile uint16_t       revents; /* received events */
	uint16_t                proto;
	void                   *mutex_lock; /* mutex for clearing revents */
	struct net             *net; /* Network */
	uint32_t                timeout; /* this is used for timeout sockets */
	wait_queue_head_t       wait; /* Signal queue */
};

#define TPROTO(psk) (psk)->pico_tproto

#define picotcp_sock(x) ((struct picotcp_sock *)x->sk)
#define psk_lock(x)     pico_mutex_lock(x->mutex_lock)
#define psk_unlock(x)   pico_mutex_unlock(x->mutex_lock)

static struct proto picotcp_proto = {
	.name     = "PICOTCP",
	.owner    = THIS_MODULE,
	.obj_size = sizeof(struct picotcp_sock),
};

static void pico_event_clear(struct picotcp_sock *psk, uint16_t events)
{
	psk_lock(psk);
	psk->revents &= ~events;
	psk_unlock(psk);
}

uint16_t pico_bsd_select(struct picotcp_sock *psk)
{
	uint16_t events = psk->events & psk->revents; /* maybe an event we are waiting for, was already queued ? */

	DEFINE_WAIT(wait);
	picotcp_dbg("Called SELECT\n");
	/* wait for one of the selected events... */
	prepare_to_wait(sk_sleep(&psk->sk), &wait, TASK_INTERRUPTIBLE);
	while (!events) {
		events = (psk->revents & psk->events); /* filter for the events we were waiting for */
		if (!events)
			schedule();
		if (signal_pending(current)) {
			psk->revents = PICO_SOCK_EV_ERR;
			break;
		}
	}
	finish_wait(sk_sleep(&psk->sk), &wait);
	picotcp_dbg("SELECT: wakeup!\n");
	/* the event we were waiting for happened, now report it */
	return events; /* return any event(s) that occurred, that we were waiting for */
}

static uint16_t pico_bsd_wait(struct picotcp_sock *psk, int read, int write, int close)
{
	psk_lock(psk);

	psk->events = PICO_SOCK_EV_ERR;
	psk->events |= PICO_SOCK_EV_FIN;
	psk->events |= PICO_SOCK_EV_CONN;
	if (close)
		psk->events |= PICO_SOCK_EV_CLOSE;
	if (read)
		psk->events |= PICO_SOCK_EV_RD;
	if (write)
		psk->events |= PICO_SOCK_EV_WR;

	psk_unlock(psk);

	picotcp_dbg("calling pico_bsd_select..\n");

	return pico_bsd_select(psk);
}

static unsigned int picotcp_poll(struct file *file, struct socket *sock, poll_table *wait)
{
	struct picotcp_sock *psk = picotcp_sock(sock);
	struct sock *sk = sock->sk;
	unsigned int mask = 0;

	picotcp_dbg("Called picotcp_poll\n");

	if ((TPROTO(psk) != PICO_PROTO_UDP)
			|| (poll_requested_events(wait) & POLLOUT))
		sock_poll_wait(file, sock, wait);

	psk_lock(psk);

	if (sk->sk_err)
		mask |= POLLERR;
	if (psk->revents & PICO_SOCK_EV_CLOSE)
		mask |= POLLHUP;
	if (psk->revents & PICO_SOCK_EV_FIN)
		mask |= POLLHUP;
	if (psk->revents & PICO_SOCK_EV_RD)
		mask |= POLLIN;
	if (psk->revents & PICO_SOCK_EV_CONN)
		mask |= POLLIN;
	if (psk->revents & PICO_SOCK_EV_WR)
		mask |= POLLOUT;

	/* Addendum: UDP can always write, by default... */
	if (TPROTO(psk) == PICO_PROTO_UDP)
		mask |= POLLOUT;

	psk_unlock(psk);

	picotcp_dbg("return from poll\n");

	return mask;
}

static void picotcp_socket_event(uint16_t ev, void *s, void *priv)
{
	struct picotcp_sock *psk = priv;

	if (!psk || !psk->mutex_lock) {
		if (ev & (PICO_SOCK_EV_CLOSE | PICO_SOCK_EV_FIN))
			rem_pico_socket_close(s);
		/* endpoint not initialized yet! */
		return;
	}

	if (psk->sk.sk_err) {
		ev = PICO_SOCK_EV_ERR | (psk->sk.sk_err << 8);
	}

	if (psk->in_use != 1)
		return;

	psk_lock(psk);

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

	psk_unlock(psk);

	/* sending the event, while no one was listening,
	 will just cause an extra loop in select() */
	picotcp_dbg("Waking up all the selects...\n");
	wake_up_interruptible(sk_sleep(&psk->sk));
}

static int picotcp_connect(struct socket *sock, struct sockaddr *_saddr, int socklen, int flags)
{
	struct picotcp_sock *psk = picotcp_sock(sock);
	union pico_address addr;
	uint16_t port;
	uint16_t ev;
	int err;

	picotcp_dbg("Called connect\n");

	if (bsd_to_pico_addr(&addr, _saddr, socklen) < 0) {
		picotcp_dbg("Connect: invalid address\n");
		return -EINVAL;
	}

	port = bsd_to_pico_port(_saddr, socklen);
	if (port == 0) {
		picotcp_dbg("Connect: invalid port\n");
		return -EINVAL;
	}

	picotcp_dbg("Calling pico_socket_connect\n");
	rem_stack_lock();
	err = rem_pico_socket_connect(psk->pico, &addr, port);
	rem_stack_unlock();
	picotcp_dbg("Calling pico_socket_connect: done\n");

	if (err) {
		return 0 - pico_err;
	}

	if (TPROTO(psk) == PICO_PROTO_UDP) {
		picotcp_dbg("UDP: Connected\n");
		pico_event_clear(psk, PICO_SOCK_EV_CONN);
		return 0;
	}

	if (flags & MSG_DONTWAIT) {
		return -EAGAIN;
	} else {
		/* wait for event */
		picotcp_dbg("Trying to establish connection...\n");
		ev = pico_bsd_wait(psk, 0, 0, 0); /* wait for ERR, FIN and CONN */
	}

	if (ev & PICO_SOCK_EV_CONN) {
		/* clear the EV_CONN event */
		picotcp_dbg("Connected\n");
		pico_event_clear(psk, PICO_SOCK_EV_CONN);
		return 0;
	} else {
		rem_pico_socket_close(psk->pico);
		psk->in_use = 0;
	}
	return -EINTR;
}

static int picotcp_bind(struct socket *sock, struct sockaddr *local_addr, int socklen)
{
	union pico_address addr;
	struct picotcp_sock *psk = picotcp_sock(sock);
	uint16_t port;

	picotcp_dbg("Called bind\n");

	if (bsd_to_pico_addr(&addr, local_addr, socklen) < 0) {
		picotcp_dbg("bind: invalid address\n");
		return -EINVAL;
	}
	port = bsd_to_pico_port(local_addr, socklen);
	picotcp_dbg("bind to port\n", short_be(port));
	/* No check for port, if == 0 use autobind */

	rem_stack_lock();
	if (rem_pico_socket_bind(psk->pico, &addr, &port) < 0) {
		rem_stack_unlock();
		picotcp_dbg("bind: failed\n");
		return 0 - pico_err;
	}
	psk->state = SOCK_BOUND;
	rem_stack_unlock();
	picotcp_dbg("Bind: success\n");
	return 0;
}

static struct picotcp_sock *picotcp_sock_new(struct sock *parent, struct net *net, int protocol)
{
	struct picotcp_sock *psk;
	struct sock *sk;

	if (!parent)
		sk = sk_alloc(net, PF_INET, GFP_KERNEL, &picotcp_proto, 0);
	else {
		sk = sk_clone_lock(parent, GFP_KERNEL);
		if (sk)
			bh_unlock_sock(sk);
	}
	if (!sk) {
		return NULL;
	}
	psk = (struct picotcp_sock *) sk;
	psk->mutex_lock = pico_mutex_init();

	psk->net = net;
	psk->state = SOCK_OPEN;
	psk->in_use = 0;
	psk->events = 0;
	psk->revents = 0;
	psk->proto = protocol;

	return psk;
}

static int picotcp_getname(struct socket *sock, struct sockaddr *local_addr, int peer)
{
	struct picotcp_sock *psk = picotcp_sock(sock);
	union pico_address addr;
	uint16_t port, proto;
	int socklen;

	picotcp_dbg("Called picotcp_getname\n");

	rem_stack_lock();
	if (rem_pico_socket_getname(psk->pico, &addr, &port, &proto) < 0) {
		rem_stack_unlock();
		return -EFAULT;
	}
	rem_stack_unlock();

	if (proto == PICO_PROTO_IPV6)
		socklen = SOCKSIZE6;
	else
		socklen = SOCKSIZE;

	if (pico_addr_to_bsd(local_addr, socklen, &addr, proto) < 0)
		return -1;

	pico_port_to_bsd(local_addr, socklen, port);
	return 0;
}

static int picotcp_accept(struct socket *sock, struct socket *newsock, int flags, bool kern)
{
	struct picotcp_sock *psk = picotcp_sock(sock);
	struct picotcp_sock *newpsk;
	uint16_t events;
	union pico_address picoaddr;
	uint16_t port;

	picotcp_dbg("Called ACCEPT\n");

	if (psk->state != SOCK_LISTEN) {
		picotcp_dbg("Invalid socket state, not listening\n");
		return -EOPNOTSUPP;
	}

	picotcp_dbg("Going to sleep...\n");
	if (flags & O_NONBLOCK)
		events = PICO_SOCK_EV_CONN;
	else
		events = pico_bsd_wait(psk, 0, 0, 0);

	picotcp_dbg("ACCEPT resumed\n");

	/* Here I check for psk again, to avoid races */
	if (!psk || !psk->in_use)
		return -EINTR;

	if (events & PICO_SOCK_EV_CONN) {
		struct rem_pico_socket *ps;
		rem_stack_lock();
		psk_lock(psk);
		ps = rem_pico_socket_accept(psk->pico, &picoaddr, &port);
		psk_unlock(psk);
		if (!ps) {
			rem_stack_unlock();
			return 0 - pico_err;
		}
		pico_event_clear(psk, PICO_SOCK_EV_CONN); /* clear the CONN event the listening socket */
		picotcp_dbg("Socket accepted: %p\n", ps);
		newpsk = picotcp_sock_new(&psk->sk, psk->net, psk->proto);
		if (!newpsk) {
			rem_stack_unlock();
			rem_pico_socket_close(ps);
			return -ENOMEM;
		}
		printk("init_data\n");
		sock_init_data(newsock, &newpsk->sk);
		newsock->sk = &newpsk->sk;
		newsock->state = SS_CONNECTED;
		newpsk->state = SOCK_CONNECTED;
		newpsk->sk.sk_state = TCP_ESTABLISHED;
		newpsk->pico = ps;
		newpsk->pico_tproto = rem_get_proto(ps);
		rem_set_priv(ps, newpsk);
		newpsk->in_use = 1;
		printk("sock_graft\n");
		sock_graft(&newpsk->sk, newsock);
		rem_stack_unlock();
		picotcp_dbg("ACCEPT: SUCCESS!\n");
		return 0;
	}
	return -EAGAIN;
}

static int picotcp_listen(struct socket *sock, int backlog)
{
	struct picotcp_sock *psk = picotcp_sock(sock);
	int err;
	struct sock *sk = sock->sk;

	picotcp_dbg("Called listen()\n");

	sk->sk_state = TCP_LISTEN;
	rem_stack_lock();
	err = rem_pico_socket_listen(psk->pico, backlog);
	rem_stack_unlock();

	if (err)
		return 0 - pico_err;

	picotcp_dbg("Listen: success\n");
	psk->state = SOCK_LISTEN;
	return 0;
}

static int picotcp_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
{
	struct picotcp_sock *psk = picotcp_sock(sock);
	int tot_len = 0;
	union pico_address addr;
	uint16_t port = 0;
	uint8_t *kbuf;

	picotcp_dbg("Called picotcp_sendmsg\n");

	if (len <= 0)
		return -EINVAL;

	if ((TPROTO(psk) == PICO_PROTO_UDP) && (len > 65535))
		len = 65535;

	kbuf = kmalloc(len, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	if (msg->msg_namelen > 0) {
		bsd_to_pico_addr(&addr, msg->msg_name, msg->msg_namelen);
		port = bsd_to_pico_port(msg->msg_name, msg->msg_namelen);
	}

	memcpy_from_msg(kbuf, msg, len); //ADI: todo return value

	while (tot_len < len) {
		int r;
		psk_lock(psk);
		if (msg->msg_namelen > 0)
			r = rem_pico_socket_sendto(psk->pico, kbuf, len, &addr, port);
		else
			r = rem_pico_socket_send(psk->pico, kbuf, len);
		psk_unlock(psk);
		picotcp_dbg("> sendto returned %d - expected len is %d\n", r, len);
		if (r < 0) {
			kfree(kbuf);
			return 0 - pico_err;
		}

		tot_len += r;

		pico_event_clear(psk, PICO_SOCK_EV_WR);
		if ((tot_len > 0) && psk->proto == PICO_PROTO_UDP)
			break;

		if (msg->msg_flags & MSG_DONTWAIT) {
			if (tot_len > 0)
				break;
			else
				return -EAGAIN;
		}

		if (tot_len < len) {
			uint16_t ev = 0;
			ev = pico_bsd_wait(psk, 0, 1, 1);
			if ((ev & (PICO_SOCK_EV_ERR | PICO_SOCK_EV_FIN)) || (ev == 0)) {
				pico_event_clear(psk, PICO_SOCK_EV_WR);
				pico_event_clear(psk, PICO_SOCK_EV_ERR);
				kfree(kbuf);
				return -EINTR;
			}
		}
	}

	picotcp_dbg("About to return from sendmsg. tot_len is %d\n", tot_len);
	kfree(kbuf);
	return tot_len;
}

static int picotcp_recvmsg(struct socket *sock, struct msghdr *msg, size_t len, int flags)
{
	struct picotcp_sock *psk = picotcp_sock(sock);
	int tot_len = 0;
	uint8_t *kbuf;
	union pico_address addr;
	uint16_t port;

	/* Keep kbuf in case of peek */
	static uint8_t *peeked_kbuf = NULL;
	static uint8_t *peeked_kbuf_start = NULL;
	static int peeked_kbuf_len = 0;

	picotcp_dbg("Called picotcp_recvmsg\n");

	if (len < 1)
		return -EINVAL;

	if (flags & MSG_PEEK) {
		printk("\n\nMSG_PEEK\n\n");
	}

	if ((TPROTO(psk) == PICO_PROTO_UDP) && (len > 65535))
		len = 65535;

	kbuf = kmalloc(len, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;
	if (peeked_kbuf) {
		if (len < peeked_kbuf_len) {
			memcpy(kbuf, peeked_kbuf, len);
			tot_len += len;
		} else {
			memcpy(kbuf, peeked_kbuf, peeked_kbuf_len);
			tot_len += peeked_kbuf_len;
		}

		/* If it is an actual read (i.e. no MSG_PEEK set),
		 * consume the bytes already taken from the saved kbuf.
		 */
		if (!(flags & MSG_PEEK)) {
			peeked_kbuf += tot_len;
			peeked_kbuf_len -= tot_len;
			/* If all bytes have been consumed, get rid of the
			 * saved buffer.
			 */
			if (peeked_kbuf_len <= 0) {
				kfree(peeked_kbuf_start);
				peeked_kbuf_start = peeked_kbuf = NULL;
				peeked_kbuf_len = 0;
			}
		}
	}

	while (tot_len < len) {
		int r;
		psk_lock(psk);
		r = rem_pico_socket_recvfrom(psk->pico, kbuf, len - tot_len, &addr, &port);
		psk_unlock(psk);
		picotcp_dbg("> recvfrom returned %d - expected len is %d\n", r,
				len - tot_len);
		if (r < 0) {
			kfree(kbuf);
			return 0 - pico_err;
		}

		tot_len += r;

		if (r == 0) {
			pico_event_clear(psk, PICO_SOCK_EV_RD);
			pico_event_clear(psk, PICO_SOCK_EV_ERR);
			if (tot_len > 0) {
				picotcp_dbg("recvfrom returning %d\n", tot_len);
				goto recv_success;
			}
		}
		if ((tot_len > 0) && (TPROTO(psk) == PICO_PROTO_UDP))
			goto recv_success;

		if (flags & MSG_DONTWAIT) {
			if (tot_len > 0)
				goto recv_success;
			else
				return -EAGAIN;
		}

		if (tot_len < len) {
			uint16_t ev = 0;
			ev = pico_bsd_wait(psk, 1, 0, 1);
			if ((ev & (PICO_SOCK_EV_ERR | PICO_SOCK_EV_FIN | PICO_SOCK_EV_CLOSE))
					|| (ev == 0)) {
				pico_event_clear(psk, PICO_SOCK_EV_RD);
				pico_event_clear(psk, PICO_SOCK_EV_ERR);
				kfree(kbuf);
				return -EINTR;
			}
		}
	}

	recv_success:
	picotcp_dbg("About to return from recvmsg. tot_len is %d\n", tot_len);
	if (msg->msg_name) {
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

	memcpy_to_msg(msg, kbuf, tot_len); // ADI TODO: check result

	/* If in PEEK Mode, and no packet stored yet,
	 * save this segment for later use.
	 */
	if ((flags & MSG_PEEK) && (!peeked_kbuf_start)) {
		peeked_kbuf_start = peeked_kbuf = kbuf;
		peeked_kbuf_len = tot_len;
	} else {
		kfree(kbuf);
	}
	if (tot_len < len) {
		pico_event_clear(psk, PICO_SOCK_EV_RD);
		pico_event_clear(psk, PICO_SOCK_EV_ERR);
	}
	picotcp_dbg("Returning from recvmsg\n");
	return tot_len;
}

static int picotcp_shutdown(struct socket *sock, int how)
{
	struct picotcp_sock *psk = picotcp_sock(sock);

	picotcp_dbg("Called picotcp_shutdown\n");

	how++; /* ... see ipv4/af_inet.c */

	if (psk->pico) /* valid socket, try to close it */
	{
		rem_stack_lock();
		rem_pico_socket_shutdown(psk->pico, how);
		rem_stack_unlock();
	}
	return 0;
}

static int picotcp_release(struct socket *sock)
{
	struct picotcp_sock *psk = picotcp_sock(sock);

	picotcp_dbg("Called picotcp_release(%p)\n", psk->pico);

	if (!psk)
		return -EINVAL;

	rem_stack_lock();
	psk_lock(psk);
	rem_pico_socket_close(psk->pico);
	psk->in_use = 0;
	psk_unlock(psk);
	rem_stack_unlock();
	mutex_destroy(psk->mutex_lock);
	sock_orphan(sock->sk);
	return 0;
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
	int option = optget(level, optname);
	struct picotcp_sock *psk = picotcp_sock(sock);
	uint8_t *val = kmalloc(*optlen, GFP_KERNEL);
	int ret;

	picotcp_dbg("Called picotcp_getsockopt\n");

	if (!psk)
		return -EINVAL;

	if (!val)
		return -ENOMEM;

	if (option < 0)
		return -EOPNOTSUPP;

	psk_lock(psk);
	ret = rem_pico_socket_getoption(psk->pico, option, val, optlen);
	psk_unlock(psk);

	if (copy_to_user(optval, val, *optlen) > 0) {
		kfree(val);
		return -EFAULT;
	}
	kfree(val);
	return ret;
}

static int picotcp_setsockopt(struct socket *sock, int level, int optname, char __user *optval, unsigned int optlen)
{
	int option = optget(level, optname);
	struct picotcp_sock *psk = picotcp_sock(sock);
	uint8_t *val = kmalloc(optlen, GFP_KERNEL);
	int ret;

	picotcp_dbg("Called picotcp_setsockopt\n");

	if (!psk)
		return -EINVAL;

	if (!val)
		return -ENOMEM;

	if (option < 0)
		return -EOPNOTSUPP;

	if (copy_from_user(val, optval, optlen))
		return -EFAULT;

	psk_lock(psk);
	ret = rem_pico_socket_setoption(psk->pico, option, val, optlen);
	psk_unlock(psk);
	kfree(val);
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
	.sendpage   = sock_no_sendpage,
	.setsockopt = picotcp_setsockopt,
	.getsockopt = picotcp_getsockopt,
	.sendmsg    = picotcp_sendmsg,
	.recvmsg    = picotcp_recvmsg,
};
EXPORT_SYMBOL(picotcp_proto_ops);

static int picotcp_create(struct net *net, struct socket *sock, int protocol, int kern)
{
	struct picotcp_sock *psk;
	struct rem_pico_socket *ps;

	picotcp_dbg("Called picotcp_create\n");

	sock->ops = &picotcp_proto_ops;

	picotcp_dbg("Selected socket type: %d\n", sock->type);
	picotcp_dbg("Selected protocol: %d\n", protocol);

	/* Convert IP sockets into DGRAM, so ioctl are still possible (e.g.: ifconfig) */
	if (sock->type == SOCK_DGRAM)
		protocol = IPPROTO_UDP;
	else
		protocol = IPPROTO_TCP;

	ps = rem_pico_socket_open(PICO_PROTO_IPV4, protocol, picotcp_socket_event);
	if (!ps)
		return 0 - pico_err;

	picotcp_dbg("Socket created: %p\n", ps);

	psk = picotcp_sock_new(NULL, net, protocol);
	if (!psk) {
		rem_pico_socket_close(ps);
		return -ENOMEM;
	}
	sock_init_data(sock, &psk->sk);
	sock->sk = &psk->sk;
	psk->pico = ps;
	psk->pico_tproto = rem_get_proto(ps);
	rem_set_priv(ps, psk);
	psk->in_use = 1;
	return 0;
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

	rc = rem_init();
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
}

MODULE_ALIAS_NETPROTO(PF_INET);
