#include <linux/of.h>
#include <linux/types.h>
#include <linux/socket.h>

extern int af_inet_picotcp_init(void);
extern int ip_route_proc_init(void);

int __init sel4ip_init(void)
{
	int rc;

	rc = af_inet_picotcp_init();
	if (rc) {
		printk(KERN_ERR "af_inet_picotcp_init() failed\n");
		return rc;
	}
	rc = ip_route_proc_init();
	if (rc) {
		printk(KERN_ERR "ip_route_proc_init() failed\n");
		return rc;
	}

	return 0;
}
fs_initcall(sel4ip_init);

