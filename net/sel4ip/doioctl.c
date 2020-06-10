#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <linux/if_arp.h>
#include <linux/in.h>
#include <linux/route.h>
#include <picotcp.h>

#include "remcalls.h"

int doioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	printk("doioctl\n");
	return -1;
}
