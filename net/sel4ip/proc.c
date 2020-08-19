#include <linux/proc_fs.h>

#include "picotcp.h"
#include "iprcchan.h"
#include "remcalls.h"

static int stack_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m,"sel4ip\n");
	return 0;
}

static int route_proc_show(struct seq_file *m, void *v)
{
	pico_routes_t  routes;
	int            i;

	seq_printf(m, "Iface\tDestination\tGateway\t\tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n");
	rem_get_routes(rem_get_chan(0), &routes);
	for (i = 0; i < routes.count; i++) {
		pico_route_t *r = &routes.routes[i];
		seq_printf(m, "%s\t%08X\t%08X\t%04X\t0\t0\t%d\t%08X\t0\t0\t0\n",
				r->devname, r->dest.ip4.addr, r->gateway.ip4.addr, r->flags,
				r->metric, r->netmask.ip4.addr);
	}
	return 0;
}

static int route_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, route_proc_show, NULL);
}

static int stack_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, stack_proc_show, NULL);
}

static const struct file_operations route_proc_fops = {
	.owner   = THIS_MODULE,
	.open    = route_proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
};

static const struct file_operations stack_proc_fops = {
	.owner   = THIS_MODULE,
	.open    = stack_proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
};

static __net_init int proc_net_route_init(struct net *net)
{
	struct proc_dir_entry *pde;

	/* /proc/net/route */
	pde = proc_create("route", S_IRUGO, net->proc_net, &route_proc_fops);
	if (!pde) {
		remove_proc_entry("route", net->proc_net);
		return -1;
	}

	/* /proc/net/stack */
	pde = proc_create("stack", S_IRUGO, net->proc_net, &stack_proc_fops);
	if (!pde) {
		remove_proc_entry("stack", net->proc_net);
		return -1;
	}
	return 0;
}

static void __net_exit proc_net_route_exit(struct net *net)
{
    remove_proc_entry("route", net->proc_net);
}

static struct pernet_operations ip_route_proc_ops __net_initdata =  {
	.init = proc_net_route_init,
	.exit = proc_net_route_exit,
};

int __init ip_route_proc_init(void)
{
	return register_pernet_subsys(&ip_route_proc_ops);
}
