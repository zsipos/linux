// SPDX-FileCopyrightText: https://github.com/danielinux/linux-emcraft/tree/master/net/tcpip
// SPDX-License-Identifier: GPL-2.0

#include <linux/if_arp.h>
#include <net/ip.h>

#include "picotcp.h"
#include "iprcchan.h"
#include "sel4ip.h"
#include "remcalls.h"

#define IOCTL_DEBUG	0

#if IOCTL_DEBUG
#define ioctl_debug printk
#else
#define ioctl_debug(...) do{}while(0)
#endif

extern void pico_stack_lock_by_chan(iprcchan_t *chan);
extern void pico_stack_unlock_by_chan(iprcchan_t *chan);

static inline void do_lock(iprcchan_t *chan)
{
	pico_stack_lock_by_chan(chan);
}

static inline void do_unlock(iprcchan_t *chan)
{
	pico_stack_unlock_by_chan(chan);
}

static iprcchan_t *get_chan(char *name)
{
	if (strcmp(name, "eth0") == 0)
		return rem_get_chan(0);
	if (strcmp(name, "lo") == 0)
		return rem_get_chan(0);
	else
		return rem_get_chan(1);
}

static int picotcp_iosgaddr(struct socket *sock, unsigned int cmd, unsigned long arg, int set)
{
	struct ifreq          _ifr, *ifr = &_ifr;
	pico_device_config_t  config;
	struct sockaddr_in   *addr;
	iprcchan_t           *chan;
	int                   ret;

	if (copy_from_user(ifr, (void*)arg, sizeof(struct ifreq)))
		return -EFAULT;
	chan = get_chan(ifr->ifr_name);
	do_lock(chan);
	ret = rem_get_device_config(chan, ifr->ifr_name, &config);
	do_unlock(chan);
	if (ret < 0)
		return -ENOENT;

	addr = (struct sockaddr_in *) &ifr->ifr_addr;

	if (set) {
		union pico_address pico_address;
		union pico_address pico_netmask;

		memset(&pico_address, 0, sizeof(pico_address));
		memset(&pico_netmask, 0, sizeof(pico_netmask));
		pico_address.ip4.addr = addr->sin_addr.s_addr;
		if (config.hasipv4link)
			pico_netmask = config.netmask;
		else
			pico_netmask.ip4.addr = htonl(0xffffff00); // default to 24 bit netmask

		do_lock(chan);
		ret = rem_set_device_address(chan, config.name, &pico_address, &pico_netmask);
		do_unlock(chan);
	}

	addr->sin_family = AF_INET;
	if (config.hasipv4link)
		addr->sin_addr.s_addr = config.address.ip4.addr;
	else
		addr->sin_addr.s_addr = 0U;

	if (copy_to_user((void*)arg, ifr, sizeof(struct ifreq)))
		return -EFAULT;
	return 0;
}

static int picotcp_iosgbrd(struct socket *sock, unsigned int cmd, unsigned long arg, int set)
{
	struct ifreq          _ifr, *ifr = &_ifr;
	pico_device_config_t  config;
	struct sockaddr_in   *addr;
	iprcchan_t           *chan;
	int                   ret;

	if (copy_from_user(ifr, (void*)arg, sizeof(struct ifreq)))
		return -EFAULT;
	chan = get_chan(ifr->ifr_name);
	do_lock(chan);
	ret = rem_get_device_config(chan, ifr->ifr_name, &config);
	do_unlock(chan);
	if (ret < 0)
		return -ENOENT;

	if (set)
		return -EOPNOTSUPP;

	addr = (struct sockaddr_in *) &ifr->ifr_addr;

	addr->sin_family = AF_INET;
	if (config.hasipv4link)
		addr->sin_addr.s_addr = config.address.ip4.addr | (~config.netmask.ip4.addr);
	else
		addr->sin_addr.s_addr = 0U;

	if (copy_to_user((void*)arg, ifr, sizeof(struct ifreq)))
		return -EFAULT;
	return 0;
}

static int picotcp_iosgmask(struct socket *sock, unsigned int cmd, unsigned long arg, int set)
{
	struct ifreq          _ifr, *ifr = &_ifr;
	pico_device_config_t  config;
	struct sockaddr_in   *addr;
	iprcchan_t           *chan;
	int                   ret;

	if (copy_from_user(ifr, (void*)arg, sizeof(struct ifreq)))
		return -EFAULT;
	chan = get_chan(ifr->ifr_name);
	do_lock(chan);
	ret = rem_get_device_config(chan, ifr->ifr_name, &config);
	do_unlock(chan);
	if (ret < 0)
		return -ENOENT;

	if (!config.hasipv4link)
		return -ENOENT;

	addr = (struct sockaddr_in *) &ifr->ifr_addr;

	if (set) {
		union pico_address pico_netmask;

		pico_netmask.ip4.addr = addr->sin_addr.s_addr;
		do_lock(chan);
		ret = rem_set_device_address(chan, config.name, &config.address, &pico_netmask);
		do_unlock(chan);
		return ret;
	}

	addr->sin_family = AF_INET;
	if (config.hasipv4link)
		addr->sin_addr.s_addr = config.netmask.ip4.addr;
	else
		addr->sin_addr.s_addr = 0U;

	if (copy_to_user((void*)arg, ifr, sizeof(struct ifreq)))
		return -EFAULT;
	return 0;
}

static int picotcp_iosgflags(struct socket *sock, unsigned int cmd, unsigned long arg, int set)
{
	struct ifreq          _ifr, *ifr = &_ifr;
	pico_device_config_t  config;
	iprcchan_t           *chan;
	int                   ret;

	if (copy_from_user(ifr, (void*)arg, sizeof(struct ifreq)))
		return -EFAULT;
	chan = get_chan(ifr->ifr_name);
	do_lock(chan);
	ret = rem_get_device_config(chan, ifr->ifr_name, &config);
	do_unlock(chan);
	if (ret < 0)
		return -ENOENT;

	/* Set flags: we only care about UP flag being reset */
	if (set && ((ifr->ifr_flags & IFF_UP) == 0)) {
		do_lock(chan);
		ret = rem_device_down(chan, config.name);
		do_unlock(chan);
		return ret;
	}

	ifr->ifr_flags = IFF_BROADCAST | IFF_MULTICAST;

	if (config.hasipv4link)
		ifr->ifr_flags |= IFF_UP | IFF_RUNNING;

	if (copy_to_user((void*)arg, ifr, sizeof(struct ifreq)))
		return -EFAULT;
	return 0;
}


static int picotcp_iosgmac(struct socket *sock, unsigned int cmd, unsigned long arg, int set)
{
	struct ifreq          _ifr, *ifr = &_ifr;
	pico_device_config_t  config;
	iprcchan_t           *chan;
	int                   ret;

	if (copy_from_user(ifr, (void*)arg, sizeof(struct ifreq)))
		return -EFAULT;
	chan = get_chan(ifr->ifr_name);
	do_lock(chan);
	ret = rem_get_device_config(chan, ifr->ifr_name, &config);
	do_unlock(chan);
	if(ret < 0)
		return -ENOENT;

	if (set)
		return -EOPNOTSUPP; /* Can't change macaddress on the fly... */

	if (config.hasmac) {
		memcpy(ifr->ifr_hwaddr.sa_data, &config.mac, PICO_SIZE_ETH);
		ifr->ifr_hwaddr.sa_family = ARPHRD_ETHER;
	} else {
		memset(&ifr->ifr_hwaddr, 0, sizeof(struct sockaddr));
		ifr->ifr_hwaddr.sa_family = ARPHRD_NONE;
	}

	if (strcmp(ifr->ifr_name, "lo") == 0) {
		ifr->ifr_hwaddr.sa_family = ARPHRD_LOOPBACK;
	}

	if (copy_to_user((void*)arg, ifr, sizeof(struct ifreq)))
		return -EFAULT;
	return 0;
}

static int picotcp_iosgmtu(struct socket *sock, unsigned int cmd, unsigned long arg, int set)
{
	struct ifreq          _ifr, *ifr = &_ifr;
	pico_device_config_t  config;
	iprcchan_t           *chan;
	int                   ret;

	if (copy_from_user(ifr, (void*)arg, sizeof(struct ifreq)))
		return -EFAULT;
	chan = get_chan(ifr->ifr_name);
	do_lock(chan);
	ret = rem_get_device_config(chan, ifr->ifr_name, &config);
	do_unlock(chan);
	if (ret < 0)
		return -ENOENT;

	if (set)
		return -EOPNOTSUPP; /* We don't support dynamic MTU now. */

	ifr->ifr_mtu = config.mtu;

	if (copy_to_user((void*)arg, ifr, sizeof(struct ifreq)))
		return -EFAULT;
	return 0;
}

static int picodev_to_ifreq(iprcchan_t *chan, const char *ifname, struct ifreq *ifr)
{
	pico_device_config_t  config;
	struct sockaddr_in   *addr = (struct sockaddr_in *) &ifr->ifr_addr;
	int                   ret;

	if (!ifr)
		return -1;

	do_lock(chan);
	ret = rem_get_device_config(chan, ifname, &config);
	do_unlock(chan);
	if (ret < 0)
		return -1;

	memset(ifr, 0, sizeof(struct ifreq));
	strncpy(ifr->ifr_name, config.name, IFNAMSIZ);
	addr->sin_family = AF_INET;
	if (config.hasipv4link)
		addr->sin_addr.s_addr = config.address.ip4.addr;
	else
		addr->sin_addr.s_addr = 0U;

	return 0;
}


static int picotcp_gifconf(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	struct ifconf   _ifc, *ifc = &_ifc;
	iprcchan_t     *chan;
	pico_devices_t  devices;
	int             ret, i, count, size = 0;

	if (copy_from_user(ifc, (void*)arg, sizeof(struct ifconf)))
		return -EFAULT;

	/* TODO: return devices from second stack */

	chan = get_chan("eth0");

	do_lock(chan);
	ret = rem_get_devices(chan, &devices);
	do_unlock(chan);
	if (ret < 0)
		return -ENOMEM;

	count = ifc->ifc_len / sizeof(struct ifreq);
	if (count > devices.count)
		count = devices.count;

	for (i = 0; i < count; i++) {
		struct ifreq ifr;

		if (picodev_to_ifreq(chan, devices.names[i], &ifr) < 0)
			return -EINVAL;
		if (copy_to_user(&ifc->ifc_req[i], &ifr, sizeof(struct ifreq)))
			return -EFAULT;
		size += sizeof(struct ifreq);
	}
	ifc->ifc_len = size;

	if (copy_to_user((void*)arg, ifc, sizeof(struct ifconf)))
		return -EFAULT;
	return 0;
}

static int picotcp_addroute(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	struct rtentry      _rte, *rte = &_rte;
	union pico_address  a, g, n;
	int                 flags = 1;
	char               *devname;
	iprcchan_t         *chan;
	int                 ret;

	if (copy_from_user(rte, (void*)arg, sizeof(struct rtentry)))
		return -EFAULT;

	memcpy(&a.ip4, &((struct sockaddr_in * )(&rte->rt_dst))->sin_addr.s_addr,
			sizeof(struct pico_ip4));
	memcpy(&g.ip4, &((struct sockaddr_in * )(&rte->rt_gateway))->sin_addr.s_addr,
			sizeof(struct pico_ip4));
	memcpy(&n.ip4, &((struct sockaddr_in * )(&rte->rt_genmask))->sin_addr.s_addr,
			sizeof(struct pico_ip4));
	a.ip4.addr &= n.ip4.addr;

	if (n.ip4.addr == 0)
		flags += 2;

	devname = rte->rt_dev;
	if (!devname)
		devname = "";

	/* TODO: link from device name in rt_dev (u32-> *char) */

	if (rte->rt_metric <= 0)
		rte->rt_metric = 1;

	chan = get_chan("eth0");
	do_lock(chan);
	ret = rem_device_addroute(chan, devname, &a, &n, &g, rte->rt_metric);
	do_unlock(chan);
	return ret;
}

static int picotcp_get_timestamp(struct socket *sock, unsigned long arg)
{
	int err;
	struct timeval tv;

	err = sock_get_timestamp(sock->sk, &tv);
	if (err)
		return err;
	if (copy_to_user((void*)arg, &tv, sizeof(struct timeval)))
		return -EFAULT;
	return 0;
}

static int picotcp_get_timestampns(struct socket *sock, unsigned long arg)
{
	int err;
	struct timespec ts;

	err = sock_get_timestampns(sock->sk, &ts);
	if (err)
		return err;
	if (copy_to_user((void*)arg, &ts, sizeof(struct timespec)))
		return -EFAULT;
	return 0;
}

static int picotcp_gmapmetric(struct socket *sock, unsigned long arg)
{
	struct ifreq _ifr, *ifr = &_ifr;
	struct ifmap m = { };

	if (copy_from_user(ifr, (void*) arg, sizeof(struct ifreq)))
		return -EFAULT;
	ifr->ifr_metric = 0;
	memcpy(&ifr->ifr_map, &m, sizeof(m));
	if (copy_to_user((void*) arg, ifr, sizeof(struct ifreq)))
		return -EFAULT;
	return 0;
}

static int picotcp_gtxqlen(struct socket *sock, unsigned long arg)
{
	struct ifreq _ifr, *ifr = &_ifr;

	if (copy_from_user(ifr, (void*)arg, sizeof(struct ifreq)))
		return -EFAULT;
    ifr->ifr_qlen = 500;
	if (copy_to_user((void*)arg, ifr, sizeof(struct ifreq)))
		return -EFAULT;
    return 0;
}

static int picotcp_do_dhcp(struct socket *sock, unsigned long _arg)
{
	struct sel4ioctl    arg;
	iprcchan_t         *chan;
	int                 ret, i;
	int                 nameserver_count;
	union pico_address  nameserver_addrs[SEL4IP_MAX_NAMESERVERS];

	if (copy_from_user(&arg, (void*)_arg, sizeof(struct sel4ioctl)))
		return -EFAULT;

	chan = get_chan(arg.ifname);
	do_lock(chan);
	ret = rem_dhcp(chan, arg.ifname, &nameserver_count, nameserver_addrs);
	do_unlock(chan);

	if (ret == 0) {
		arg.dhcp.nameserver_count = nameserver_count;
		for(i = 0; i < nameserver_count; i++) {
			struct sockaddr_in *p = (struct sockaddr_in*)&arg.dhcp.nameserver_addrs[i];

			p->sin_family = AF_INET;
			memcpy(&p->sin_addr.s_addr,	&nameserver_addrs[i].ip4, sizeof(struct pico_ip4));
		}
	}

	if (copy_to_user((void*)_arg, &arg, sizeof(struct sel4ioctl)))
		return -EFAULT;

	return ret;
}

static int picotcp_do_ping(struct socket *sock, unsigned long _arg)
{
	struct sel4ioctl    arg;
	iprcchan_t         *chan;
	int                 ret;
	union pico_address  addr;

	if (copy_from_user(&arg, (void*)_arg, sizeof(struct sel4ioctl)))
		return -EFAULT;

	if ((arg.ping.count < 1) || (arg.ping.count > SEL4IP_MAX_PING))
		return -EINVAL;

	memcpy(&addr.ip4, &((struct sockaddr_in*)(&arg.ping.addr))->sin_addr.s_addr, sizeof(struct pico_ip4));

	chan = get_chan(arg.ifname);
	do_lock(chan);
	ret = rem_ping(chan, &addr, arg.ping.count, arg.ping.stats);
	do_unlock(chan);

	if (copy_to_user((void*)_arg, &arg, sizeof(struct sel4ioctl)))
		return -EFAULT;

	return ret;
}

static int picotcp_do_timer(struct socket *sock, unsigned long _arg)
{
	struct sel4ioctl    arg;
	iprcchan_t         *chan;
	int                 ret;

	if (copy_from_user(&arg, (void*)_arg, sizeof(struct sel4ioctl)))
		return -EFAULT;

	chan = get_chan(arg.ifname);
	do_lock(chan);
	ret = rem_timer(chan, &arg.timer.val);
	do_unlock(chan);

	if (copy_to_user((void*)_arg, &arg, sizeof(struct sel4ioctl)))
		return -EFAULT;

	return ret;
}

int doioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	int err;

	if (!arg)
		return -EINVAL;

	ioctl_debug("ioctl(%u,%lu)\n", cmd, arg);

	switch (cmd) {
	case SIOCGSTAMP:
		err = picotcp_get_timestamp(sock, arg);
		break;
	case SIOCGSTAMPNS:
		err = picotcp_get_timestampns(sock, arg);
		break;
	case SIOCGIFCONF:
		err = picotcp_gifconf(sock, cmd, arg);
		break;
	case SIOCGIFFLAGS:
		err = picotcp_iosgflags(sock, cmd, arg, 0);
		break;
	case SIOCGIFHWADDR:
		err = picotcp_iosgmac(sock, cmd, arg, 0);
		break;
	case SIOCGIFMTU:
		err = picotcp_iosgmtu(sock, cmd, arg, 0);
		break;
	case SIOCGIFADDR:
	case SIOCGIFDSTADDR:
		err = picotcp_iosgaddr(sock, cmd, arg, 0);
		break;
	case SIOCGIFBRDADDR:
		err = picotcp_iosgbrd(sock, cmd, arg, 0);
		break;
	case SIOCGIFNETMASK:
		err = picotcp_iosgmask(sock, cmd, arg, 0);
		break;
	case SIOCGIFMETRIC:
	case SIOCGIFMAP:
		err = picotcp_gmapmetric(sock, arg);
		break;
	case SIOCGIFTXQLEN:
		err = picotcp_gtxqlen(sock, arg);
		break;

		/* Set functions */

	case SIOCSIFADDR:
		err = picotcp_iosgaddr(sock, cmd, arg, 1);
		break;
	case SIOCSIFBRDADDR:
		err = picotcp_iosgbrd(sock, cmd, arg, 1);
		break;
	case SIOCSIFNETMASK:
		err = picotcp_iosgmask(sock, cmd, arg, 1);
		break;
	case SIOCSIFFLAGS:
		err = picotcp_iosgflags(sock, cmd, arg, 1);
		break;
	case SIOCADDRT:
		err = picotcp_addroute(sock, cmd, arg);
		break;

		/* SEL4IP specific */

	case SIOCSEL4IPDHCP:
		err = picotcp_do_dhcp(sock, arg);
		break;
	case SIOCSEL4IPPING:
		err = picotcp_do_ping(sock, arg);
		break;
	case SIOCSEL4IPTIMER:
		err = picotcp_do_timer(sock, arg);
		break;


	default:
		err = -EOPNOTSUPP;
	}
	ioctl_debug("returning %d\n", err);
	return err;
}
