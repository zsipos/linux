/*
 * spi-zsipos-m.c -- ZSIPOS SPI-M controller driver
 *
 * Author: Stefan Adams
 *
 * Copyright (C) 2019 Stefan Adams
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/dmaengine.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/spi/spi.h>
#include <soc/litex/litex.h>

#define DRIVER_NAME "zsipos_spim"

#define LITEX_SPIM_EV_STATUS_REG     LITEX_CSR_OFFSET(0)  // u8
#define LITEX_SPIM_EV_PENDING_REG    LITEX_CSR_OFFSET(1)  // u8
#define LITEX_SPIM_EV_ENABLE_REG     LITEX_CSR_OFFSET(2)  // u8
#define LITEX_SPIM_MODE_REG          LITEX_CSR_OFFSET(3)  // u8
#define LITEX_SPIM_DIVCLK_REG        LITEX_CSR_OFFSET(4)  // u16
#define LITEX_SPIM_LENGTH_REG        LITEX_CSR_OFFSET(6)  // u16
#define LITEX_SPIM_CONTROL_REG       LITEX_CSR_OFFSET(8)  // u8
#define LITEX_SPIM_CS_REG            LITEX_CSR_OFFSET(9)  // u8
#define LITEX_SPIM_STATUS_REG        LITEX_CSR_OFFSET(10) // u8
#define LITEX_SPIM_TXADR_REG         LITEX_CSR_OFFSET(11) // u32
#define LITEX_SPIM_RXADR_REG         LITEX_CSR_OFFSET(15) // u32

#define LITEX_SPIM_CONTROL_START     (1<<0)
#define LITEX_SPIM_CONTROL_NOSND     (1<<1)
#define LITEX_SPIM_CONTROL_NORCV     (1<<2)

#define LITEX_SPIM_MODE_CPOL         (1<<0)
#define LITEX_SPIM_MODE_CPHA         (1<<1)
#define LITEX_SPIM_MODE_CS_HIGH      (1<<2)

#define LITEX_SPIM_STATUS_RUNNING    (1<<0)

#define LITEX_SPIM_USE_IRQ_THRESHOLD 4 // 0 = always use irq

struct zsipos_spim {
	struct spi_master	*master;
	struct clk          *clk;
	void	__iomem		*csr_base;
	void	__iomem		*mem_base;
	u32                 mem_addr; // physical address
	u32			        mem_size;
	int                 irq;
	bool                irq_enabled;
	struct completion   transferdone;
	unsigned long		clockspeed;
	u32					last_speed;
	u16					last_mode;
	u32					max_speed;
	u32					min_speed;
};

/*
 * Called only when no transfer is active on the bus... this may
 * touch registers.
 */
static int zsipos_spim_setup_transfer(struct spi_device *spi, struct spi_transfer *t)
{
	struct zsipos_spim *zsipos_spim;
	u32 speed;

	zsipos_spim = spi_master_get_devdata(spi->master);

	if (t)
		speed = t->speed_hz ? t->speed_hz : spi->max_speed_hz;
	else
		speed = spi->max_speed_hz;

	if (spi->mode != zsipos_spim->last_mode) {
		u8 mode = 0;

		if (spi->mode & SPI_CPOL)
			mode |= LITEX_SPIM_MODE_CPOL;
		if (spi->mode & SPI_CPHA)
			mode |= LITEX_SPIM_MODE_CPHA;
		if (spi->mode & SPI_CS_HIGH)
			mode |= LITEX_SPIM_MODE_CS_HIGH;

		litex_csr_writeb(mode, zsipos_spim->csr_base + LITEX_SPIM_MODE_REG);
		zsipos_spim->last_mode = spi->mode;
	}

	if (speed != zsipos_spim->last_speed) {
		unsigned long clockspeed = zsipos_spim->clockspeed;
		unsigned i;

		for (i = 0; i < (2<<16); i++)
			if (DIV_ROUND_UP(clockspeed, ((i+1)*2)) <= speed)
				break;

		litex_csr_writew(i, zsipos_spim->csr_base + LITEX_SPIM_DIVCLK_REG);
		zsipos_spim->last_speed = speed;
	}

	return 0;
}

static void zsipos_spim_set_cs(struct zsipos_spim *zsipos_spim, int mask)
{
	litex_csr_writeb(mask, zsipos_spim->csr_base + LITEX_SPIM_CS_REG);
}

static irqreturn_t zsipos_spim_irq(int irq, void *dev_id)
{
	struct zsipos_spim *zsipos_spim = dev_id;
	u8 reg;

	reg = litex_csr_readb(zsipos_spim->csr_base + LITEX_SPIM_EV_PENDING_REG);
	if (reg) {
		litex_csr_writeb(reg, zsipos_spim->csr_base + LITEX_SPIM_EV_PENDING_REG);
		complete(&zsipos_spim->transferdone);
	}

	return IRQ_HANDLED;
}

static void zsipos_spim_enable_irq(struct zsipos_spim *zsipos_spim, bool enabled)
{
	if (zsipos_spim->irq_enabled != enabled) {
		zsipos_spim->irq_enabled = enabled;
		litex_csr_writeb(enabled, zsipos_spim->csr_base + LITEX_SPIM_EV_ENABLE_REG);
	}
}

static void zsipos_spim_xfer_mem(struct zsipos_spim *zsipos_spim, const u8 *txdata, u8 *rxdata, unsigned len)
{
	u8 control = LITEX_SPIM_CONTROL_START;

	if (txdata)
		memcpy_toio(zsipos_spim->mem_base, txdata, len);
	else
		control |= LITEX_SPIM_CONTROL_NOSND;

	if (!rxdata)
		control |= LITEX_SPIM_CONTROL_NORCV;

	reinit_completion(&zsipos_spim->transferdone);

	litex_csr_writew(len, zsipos_spim->csr_base + LITEX_SPIM_LENGTH_REG);
	litex_csr_writeb(control, zsipos_spim->csr_base + LITEX_SPIM_CONTROL_REG);

	wait_for_completion(&zsipos_spim->transferdone);

	if (rxdata)
		memcpy_fromio(rxdata, zsipos_spim->mem_base, len);
}

static void zsipos_spim_xfer_mini(struct zsipos_spim *zsipos_spim, const u8 *txdata, u8 *rxdata, unsigned len)
{
	u8 control = LITEX_SPIM_CONTROL_START;
	u8 __iomem *mem = zsipos_spim->mem_base;
	int i;

	zsipos_spim_enable_irq(zsipos_spim, false);

	if (txdata) {
		for (i = 0; i < len; i++)
			mem[i] = txdata[i];
	} else
		control |= LITEX_SPIM_CONTROL_NOSND;

	if (!rxdata)
		control |= LITEX_SPIM_CONTROL_NORCV;

	litex_csr_writew(len, zsipos_spim->csr_base + LITEX_SPIM_LENGTH_REG);
	litex_csr_writeb(control, zsipos_spim->csr_base + LITEX_SPIM_CONTROL_REG);

	while(litex_csr_readb(zsipos_spim->csr_base + LITEX_SPIM_STATUS_REG))
		cond_resched();

	if (rxdata) {
		for (i = 0; i < len; i++)
			rxdata[i] = mem[i];
	}
}

static void zsipos_spim_xfer_chunk(struct zsipos_spim *zsipos_spim, const u8 *txdata, u8 *rxdata, unsigned len)
{
	if (len < LITEX_SPIM_USE_IRQ_THRESHOLD)
		zsipos_spim_xfer_mini(zsipos_spim, txdata, rxdata, len);
	else {
		unsigned int memsize = zsipos_spim->mem_size;
		unsigned int i, r = len % memsize;

		zsipos_spim_enable_irq(zsipos_spim, true);

		for (i = 0; i < len / memsize; i++) {
			zsipos_spim_xfer_mem(zsipos_spim, txdata, rxdata, memsize);
			if (txdata) txdata += memsize;
			if (rxdata) rxdata += memsize;
		}
		if (r)
			zsipos_spim_xfer_mem(zsipos_spim, txdata, rxdata, r);
	}
}

static unsigned zsipos_spim_write_read(struct zsipos_spim *zsipos_spim, struct spi_transfer *xfer)
{
	zsipos_spim_xfer_chunk(zsipos_spim, xfer->tx_buf, xfer->rx_buf, xfer->len);
	return xfer->len;
}

static unsigned zsipos_spim_write_read_dma(struct zsipos_spim *zsipos_spim, struct spi_transfer *xfer)
{
	u8 control = LITEX_SPIM_CONTROL_START;

	zsipos_spim_enable_irq(zsipos_spim, true);

	if (xfer->tx_dma)
		litex_csr_writel(xfer->tx_dma, zsipos_spim->csr_base + LITEX_SPIM_TXADR_REG);
	else
		control |= LITEX_SPIM_CONTROL_NOSND;

	if (xfer->rx_dma)
		litex_csr_writel(xfer->rx_dma, zsipos_spim->csr_base + LITEX_SPIM_RXADR_REG);
	else
		control |= LITEX_SPIM_CONTROL_NORCV;

	reinit_completion(&zsipos_spim->transferdone);

	litex_csr_writew(xfer->len, zsipos_spim->csr_base + LITEX_SPIM_LENGTH_REG);
	litex_csr_writeb(control, zsipos_spim->csr_base + LITEX_SPIM_CONTROL_REG);

	wait_for_completion(&zsipos_spim->transferdone);

	return xfer->len;
}

static bool zsipos_spim_can_dma(struct spi_master *master, struct spi_device *spi,
		struct spi_transfer *xfer)
{
	// we only support is_dma_mapped at the moment
	return false;
}

static int zsipos_spim_transfer_one_message(struct spi_master *master, struct spi_message *m)
{
	struct zsipos_spim *zsipos_spim = spi_master_get_devdata(master);
	struct spi_device *spi = m->spi;
	struct spi_transfer *t;
	int status;
	int cs_active = 0;

	list_for_each_entry(t, &m->transfers, transfer_list) {
		status = zsipos_spim_setup_transfer(spi, t);
		if (status < 0)
			goto msg_done;

		if (!cs_active) {
			zsipos_spim_set_cs(zsipos_spim, (1 << spi->chip_select));
			cs_active = 1;
		}

		if (t->len) {
			if (master->can_dma) {
				if (m->is_dma_mapped)
					m->actual_length += zsipos_spim_write_read_dma(zsipos_spim, t);
				else {
					litex_csr_writel(zsipos_spim->mem_addr, zsipos_spim->csr_base + LITEX_SPIM_TXADR_REG);
					litex_csr_writel(zsipos_spim->mem_addr, zsipos_spim->csr_base + LITEX_SPIM_RXADR_REG);
					m->actual_length += zsipos_spim_write_read(zsipos_spim, t);
				}
			} else
				m->actual_length += zsipos_spim_write_read(zsipos_spim, t);
		}

		if (t->delay_usecs)
			udelay(t->delay_usecs);

		if (t->cs_change) {
			zsipos_spim_set_cs(zsipos_spim, 0);
			cs_active = 0;
		}
	}

msg_done:

	if (cs_active)
		zsipos_spim_set_cs(zsipos_spim, 0);

	m->status = status;
	spi_finalize_current_message(master);

	return 0;
}

static int zsipos_spim_reset(struct zsipos_spim *zsipos_spim)
{
	zsipos_spim_set_cs(zsipos_spim, 0);
	litex_csr_writeb(1, zsipos_spim->csr_base + LITEX_SPIM_EV_PENDING_REG);
	litex_csr_writeb(0, zsipos_spim->csr_base + LITEX_SPIM_EV_ENABLE_REG);
	zsipos_spim_enable_irq(zsipos_spim, false);

	return 0;
}

/*
 * The setup function configures the spi_device for communcation via
 * this controller.  This function may be called at any time and should
 * not touch registers.
 */
static int zsipos_spim_setup(struct spi_device *spi)
{
	struct zsipos_spim *zsipos_spim;

	zsipos_spim = spi_master_get_devdata(spi->master);

	if ((spi->max_speed_hz == 0)
			|| (spi->max_speed_hz > zsipos_spim->max_speed))
		spi->max_speed_hz = zsipos_spim->max_speed;

	if (spi->max_speed_hz < zsipos_spim->min_speed) {
		dev_err(&spi->dev, "setup: requested speed too low %d Hz\n",
				spi->max_speed_hz);
		return -EINVAL;
	}

	/*
	 * baudrate & width will be set by zsipos_spim_setup_transfer
	 */

	return 0;
}

static int zsipos_spim_probe(struct platform_device *pdev)
{
	struct spi_master *master;
	struct zsipos_spim *spi;
	struct resource *r;
	int status = 0;
	u32 val;

	master = spi_alloc_master(&pdev->dev, sizeof *spi);
	if (master == NULL) {
		dev_dbg(&pdev->dev, "master allocation failed\n");
		return -ENOMEM;
	}

	if (pdev->id != -1)
		master->bus_num = pdev->id;

	master->bus_num = -1;

	master->mode_bits = SPI_CPHA | SPI_CPOL | SPI_CS_HIGH;
	master->bits_per_word_mask = SPI_BPW_MASK(8);

	master->setup = zsipos_spim_setup;
	master->transfer_one_message = zsipos_spim_transfer_one_message;

	status = of_property_read_u32(pdev->dev.of_node, "cs-width", &val);
	if (status) {
		dev_err(&pdev->dev, "unable to get cs-width\n");
		goto out;
	}
	master->num_chipselect = val;

	status = of_property_read_u32(pdev->dev.of_node, "can-dma", &val);
	if (status == 0 && val) {
		dev_info(&pdev->dev, "dma enabled\n");
		master->can_dma = zsipos_spim_can_dma;
		master->dma_alignment = 4;
	}
	status = 0;

#ifdef CONFIG_OF
	master->dev.of_node = pdev->dev.of_node;
#endif

	platform_set_drvdata(pdev, master);

	spi = spi_master_get_devdata(master);
	spi->master = master;

	init_completion(&spi->transferdone);

	spi->clk = devm_clk_get(&pdev->dev, NULL);
	if (IS_ERR(spi->clk)) {
		dev_err(&pdev->dev, "Unable to find bus clock\n");
		status = PTR_ERR(spi->clk);
		goto out;
	}

	spi->clockspeed = clk_get_rate(spi->clk);
	spi->max_speed  = spi->clockspeed / (1<<1);
	spi->min_speed  = spi->clockspeed / (1<<16);

	spi->last_speed = -1;
	spi->last_mode  = -1;


	r = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (r == NULL) {
		status = -ENODEV;
		goto out;
	}
	if (!devm_request_mem_region(&pdev->dev, r->start, resource_size(r),
			dev_name(&pdev->dev))) {
		status = -EBUSY;
		goto out;
	}
	spi->csr_base = devm_ioremap_nocache(&pdev->dev, r->start,
			resource_size(r));
	if (IS_ERR(spi->csr_base)) {
		status = PTR_ERR(spi->csr_base);
		goto out;
	}

	r = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	if (r == NULL) {
		status = -ENODEV;
		goto out;
	}
	spi->mem_addr = r->start;
	if (!devm_request_mem_region(&pdev->dev, r->start, resource_size(r),
			dev_name(&pdev->dev))) {
		status = -EBUSY;
		goto out;
	}
	spi->mem_base = devm_ioremap_nocache(&pdev->dev, r->start,
			resource_size(r));
	if (IS_ERR(spi->mem_base)) {
		status = PTR_ERR(spi->mem_base);
		goto out;
	}

	status = of_property_read_u32(pdev->dev.of_node, "mem-size",
			&spi->mem_size);
	if (status) {
		dev_err(&pdev->dev, "unable to get mem-size\n");
		goto out;
	}

	spi->irq = platform_get_irq(pdev, 0);

	status = request_irq(spi->irq, zsipos_spim_irq, 0, DRIVER_NAME, spi);
	if (status < 0) {
		dev_err(&pdev->dev, DRIVER_NAME ": request irq %d failed "
				"(status = %d)\n", spi->irq, status);
		goto out;
	}

	zsipos_spim_reset(spi);

	status = spi_register_master(master);

	dev_info(&pdev->dev, "loaded\n");

	return status;

out:
	spi_master_put(master);
	return status;
}

static int zsipos_spim_remove(struct platform_device *pdev)
{
	struct spi_master *master;
	struct zsipos_spim *spi;

	master = platform_get_drvdata(pdev);
	spi = spi_master_get_devdata(master);

	spi_unregister_master(master);

	free_irq(spi->irq, spi);

	return 0;
}

static const struct of_device_id zsipos_spim_match[] = {
	{ .compatible = "zsipos,spi-m" },
	{},
};
MODULE_DEVICE_TABLE(of, zsipos_spim_match);

static struct platform_driver zsipos_spim_driver = {
	.probe = zsipos_spim_probe,
	.remove = zsipos_spim_remove,
	.driver = {
		.name	= DRIVER_NAME,
		.owner	= THIS_MODULE,
		.of_match_table = zsipos_spim_match
	}
};
module_platform_driver(zsipos_spim_driver);

MODULE_DESCRIPTION("zsipos spi-m driver");
MODULE_AUTHOR("Stefan Adams");
MODULE_LICENSE("GPL");
