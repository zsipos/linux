#include <linux/interrupt.h>
#include <linux/types.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/mutex.h>

#include "iprcchan.h"

typedef struct iprcchan {
	// master
	u8 __iomem        *m_request_reg;
	u8 __iomem        *m_confirm_reg;
	u8 __iomem        *m_buffer;
	int                m_confirm_irq;
	struct completion  m_complete;
	struct mutex       m_lock;
	// slave
	u8 __iomem        *s_request_reg;
	u8 __iomem        *s_confirm_reg;
	u8 __iomem        *s_buffer;
	int                s_request_irq;
	// slave callback
	void             (*cb_func)(void *cb_data, void *buffer);
	void              *cb_data;
} iprcchan_t;

static irqreturn_t iprcchan_master_irq(int irq, void *devid)
{
	iprcchan_t *chan = devid;

	*chan->m_confirm_reg = 0;
	complete(&chan->m_complete);
	return IRQ_HANDLED;
}

static irqreturn_t iprcchan_slave_irq(int irq, void *devid)
{
	iprcchan_t *chan = devid;

	if (*chan->s_request_reg) {
		*chan->s_request_reg = 0;
		return IRQ_WAKE_THREAD;
	}
	return IRQ_NONE;
}

static irqreturn_t iprcchan_slave_irq_threaded(int irq, void *devid)
{
	iprcchan_t *chan = devid;

	chan->cb_func(chan->cb_data, chan->s_buffer);
	*chan->s_confirm_reg = 1;
	return IRQ_HANDLED;
}

struct device_node *open_node(int num, int master)
{
	char nodename[22];

	if (master)
		strcpy(nodename, "/soc/to_sel4_master@X");
	else
		strcpy(nodename, "/soc/to_linux_slave@X");
	nodename[sizeof(nodename)-2] = '0' + num;

	return of_find_node_by_path(nodename);
}

static void *get_and_map_reg(struct device_node *node, int offset)
{
	int rc;
	struct resource resource;

	rc = of_address_to_resource(node, offset, &resource);
	if (rc)
		return NULL;
	return ioremap_nocache(resource.start, resource_size(&resource));
}

iprcchan_t *iprcchan_open(int num, void (*cb_func)(void *cb_data, void *buffer), void *cb_data)
{
	iprcchan_t    *chan = NULL;
	struct device_node *master_node, *slave_node;

	if (num > 0) {
		printk(KERN_ERR "illegal channel number %d.\n", num);
		return NULL;
	}

	/* read of configuration from devicetree */

	master_node = open_node(num, 1);
	slave_node = open_node(num, 0);
	if (!master_node || !slave_node) {
		printk(KERN_ERR "can node find devicetree entries\n");
		return NULL;
	}

	chan = kmalloc(sizeof(iprcchan_t), GFP_KERNEL);
	if (!chan)
		goto error;
	memset(chan, 0, sizeof(*chan));

	/* get master resources */

	init_completion(&chan->m_complete);
	mutex_init(&chan->m_lock);

	chan->m_request_reg = get_and_map_reg(master_node, 0);
	chan->m_confirm_reg = get_and_map_reg(master_node, 1);
	chan->m_buffer = get_and_map_reg(master_node, 2);
	if (!chan->m_request_reg || !chan->m_confirm_reg || !chan->m_buffer) {
		printk(KERN_ERR "can not map master registers\n");
		goto error;
	}

	chan->m_confirm_irq = irq_of_parse_and_map(master_node, 0);
	if (chan->m_confirm_irq < 0) {
		printk(KERN_ERR "can not get master irq resource\n");
		goto error;
	}

	if(request_irq(chan->m_confirm_irq, iprcchan_master_irq, 0, "iprcchanm", chan)) {
		printk(KERN_ERR "can not map master irq\n");
		goto error;
	}

	/* get slave resources */

	chan->cb_func = cb_func;
	chan->cb_data = cb_data;

	chan->s_request_reg = get_and_map_reg(slave_node, 0);
	chan->s_confirm_reg = get_and_map_reg(slave_node, 1);
	chan->s_buffer = get_and_map_reg(slave_node, 2);
	if (!chan->s_request_reg || !chan->s_confirm_reg || !chan->s_buffer) {
		printk(KERN_ERR "can not map slave registers\n");
		goto error;
	}

	chan->s_request_irq = irq_of_parse_and_map(slave_node, 0);
	if (chan->s_request_irq < 0) {
		printk(KERN_ERR "can not get slave irq resource\n");
		goto error;
	}

	if(request_threaded_irq(chan->s_request_irq, iprcchan_slave_irq, iprcchan_slave_irq_threaded, 0, "iprcchans", chan)) {
		printk(KERN_ERR "can not map slave irq\n");
		goto error;
	}

	return chan;

error:

	iprcchan_close(chan);
	return NULL;
}

void iprcchan_close(iprcchan_t *chan)
{
	if (!chan)
		return;

	/* free master resources */

	if (chan->m_confirm_irq)
		free_irq(chan->m_confirm_irq, chan);
	if (chan->m_request_reg)
		iounmap(chan->m_request_reg);
	if (chan->m_confirm_reg)
		iounmap(chan->m_confirm_reg);
	if (chan->m_buffer)
		iounmap(chan->m_buffer);

	/* free slave resources */

	if (chan->s_request_irq)
		free_irq(chan->s_request_irq, chan);
	if (chan->s_request_reg)
		iounmap(chan->s_request_reg);
	if (chan->s_confirm_reg)
		iounmap(chan->s_confirm_reg);
	if (chan->s_buffer)
		iounmap(chan->s_buffer);

	mutex_destroy(&chan->m_lock);

	kfree(chan);
}

void *iprcchan_begin_call(iprcchan_t *chan)
{
	mutex_lock(&chan->m_lock);
	return chan->m_buffer;
}

int iprcchan_do_call(iprcchan_t *chan)
{
	*chan->m_request_reg = 1;
	wait_for_completion(&chan->m_complete);
	return 0;
}

void iprcchan_end_call(iprcchan_t *chan)
{
	mutex_unlock(&chan->m_lock);
}
