#include "picotcp.h"
#include "iprcchan.h"
#include "remcalls.h"

#define ioctl_debug(...) do{}while(0)
//#define ioctl_debug printk

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

	if (copy_from_user(ifr, (void*)arg, sizeof(struct ifreq)))
		return -EFAULT;
	if (rem_get_device_config(get_chan(ifr->ifr_name), ifr->ifr_name, &config) < 0)
		return -ENOENT;

	addr = (struct sockaddr_in *) &ifr->ifr_addr;

	if (set) {
		union pico_address pico_address;
		union pico_address pico_netmask;

		pico_address.ip4.addr = addr->sin_addr.s_addr;
		if (config.hasipv4link)
			pico_netmask = config.netmask;
		else
			pico_netmask.ip4.addr = htonl(0xffffff00); // default to 24 bit netmask

		return rem_set_device_address(get_chan(ifr->ifr_name), config.name, &pico_address, &pico_netmask);
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

	if (copy_from_user(ifr, (void*)arg, sizeof(struct ifreq)))
		return -EFAULT;
	if (rem_get_device_config(get_chan(ifr->ifr_name), ifr->ifr_name, &config) < 0)
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

	if (copy_from_user(ifr, (void*)arg, sizeof(struct ifreq)))
		return -EFAULT;
	if (rem_get_device_config(get_chan(ifr->ifr_name), ifr->ifr_name, &config) < 0)
		return -ENOENT;

	if (!config.hasipv4link)
		return -ENOENT;

	addr = (struct sockaddr_in *) &ifr->ifr_addr;

	if (set) {
		union pico_address pico_netmask;

		pico_netmask.ip4.addr = addr->sin_addr.s_addr;
		return rem_set_device_address(get_chan(ifr->ifr_name), config.name, &config.address, &pico_netmask);
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

	if (copy_from_user(ifr, (void*)arg, sizeof(struct ifreq)))
		return -EFAULT;
	if (rem_get_device_config(get_chan(ifr->ifr_name), ifr->ifr_name, &config) < 0)
		return -ENOENT;

	/* Set flags: we only care about UP flag being reset */
	if (set && ((ifr->ifr_flags & IFF_UP) == 0)) {
		return rem_device_down(get_chan(ifr->ifr_name), config.name);
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

	if (copy_from_user(ifr, (void*)arg, sizeof(struct ifreq)))
		return -EFAULT;
	if (rem_get_device_config(get_chan(ifr->ifr_name), ifr->ifr_name, &config) < 0)
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

	if (copy_from_user(ifr, (void*)arg, sizeof(struct ifreq)))
		return -EFAULT;
	if (rem_get_device_config(get_chan(ifr->ifr_name), ifr->ifr_name, &config) < 0)
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

	if (!ifr)
		return -1;
	if (rem_get_device_config(chan, ifname, &config) < 0)
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
	int             i, count, size = 0;

	if (copy_from_user(ifc, (void*)arg, sizeof(struct ifconf)))
		return -EFAULT;

	/* TODO: return devices from second stack */

	chan = get_chan("eth0");

	if (rem_get_devices(chan, &devices) < 0)
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

	return rem_device_addroute(get_chan("eth0"), devname, &a, &n, &g, rte->rt_metric);
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

	default:
		err = -EOPNOTSUPP;
	}
	ioctl_debug("returning %d\n", err);
	return err;
}
