#include <linux/interrupt.h>
#include <linux/types.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/socket.h>

static u8 __iomem volatile *mmem;
static u8 __iomem volatile *smem;
static u8 __iomem volatile *bmem;

static int count = 0;

static irqreturn_t master_irq(int irq, void *dev_id)
{
	printk("master irq\n", *mmem);
	printk("data = %s\n", bmem);
	*smem = 0;
	if (count < 10) {
		printk("call again\n");
		count++;
		*mmem = 1;
	}
	return IRQ_HANDLED;
}

static irqreturn_t slave_irq(int irq, void *dev_id)
{
	printk("slave irq\n");
	*mmem = 0;
	*smem = 1;
	return IRQ_HANDLED;
}

int __init sel4ip_init(void) {
	struct device_node *mn, *sn;
	struct resource memm_res, mems_res, memb_res;
	int irqm, irqs;
	int rc;

	mn = of_find_node_by_path("/soc/to_sel4_master@0");
	sn = of_find_node_by_path("/soc/to_sel4_slave@0");

	rc = of_address_to_resource(mn, 0, &memm_res);
	rc = of_address_to_resource(mn, 1, &mems_res);
	rc = of_address_to_resource(mn, 2, &memb_res);

	mmem = ioremap_nocache(memm_res.start, resource_size(&memm_res));
	smem = ioremap_nocache(mems_res.start, resource_size(&mems_res));
	bmem = ioremap_nocache(memb_res.start, resource_size(&memb_res));

	irqm = irq_of_parse_and_map(mn, 0);
	//irqs = irq_of_parse_and_map(sn, 0);

	rc = request_irq(irqm, master_irq, 0, "irqm", mmem);
	//rc = request_irq(irqs, slave_irq, 0, "irqs", smem);

	strcpy(bmem, "Hello, SEL4!");
	*mmem = 1;

	printk("NET: sel4ip initialized\n");
	return 0;
}

fs_initcall(sel4ip_init);

