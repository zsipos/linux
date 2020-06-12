#include <linux/of.h>
#include <linux/types.h>
#include <linux/socket.h>

extern int af_inet_picotcp_init(void);

int __init sel4ip_init(void)
{
	return af_inet_picotcp_init();
}
fs_initcall(sel4ip_init);

