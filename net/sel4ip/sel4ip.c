#include <linux/of.h>
#include <linux/types.h>
#include <linux/socket.h>

#include "iprcchan.h"

static void iprcchan_test(void)
{
	struct iprcchan *chan;
	void *buf;

	printk("NET: sel4ip initialize\n");

	chan = iprcchan_open(0, NULL, NULL);

	buf = iprcchan_begin_call(chan);
	strcpy((char*)buf, "Hello, SEL4!\n");
	iprcchan_do_call(chan);
	printk("result: %s\n", (char*)buf);
	iprcchan_end_call(chan);

	iprcchan_close(chan);

	printk("NET: sel4ip initialize done\n");
}


int __init sel4ip_init(void) {
	iprcchan_test();
	return 0;
}

fs_initcall(sel4ip_init);

