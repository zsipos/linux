/*
 * spi-zsipos.c -- ZSIPOS SPI controller driver
 *
 * Author: Stefan Adams
 *
 * Copyright (C) 2019 Stefan Adams
 *
 * Derived from spi-oc-simple.c
 *
 * Copyright (C) 2010 South Pole AB
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/delay.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/spi/spi.h>

#define DRIVER_NAME					"zsipos_spi"
#define FIFOSIZE 					256
#define MINIRQ						2

#define ZSIPOS_SPI_NUM_CHIPSELECTS	8
#define ZSIPOS_SPI_FILL_BYTE		0x00

#define BUSALIGN					8
#define ZSIPOS_SPI_REG_SPCR			(0x0*BUSALIGN)
#define ZSIPOS_SPI_REG_SPSR			(0x1*BUSALIGN)
#define ZSIPOS_SPI_REG_SPDR			(0x2*BUSALIGN)
#define ZSIPOS_SPI_REG_SPER			(0x3*BUSALIGN)
#define ZSIPOS_SPI_REG_SSR			(0x4*BUSALIGN)
#define ZSIPOS_SPI_REG_ICNT			(0x5*BUSALIGN)

#define ZSIPOS_SPI_SPCR_SPIE		(1 << 7)
#define ZSIPOS_SPI_SPCR_SPEN		(1 << 6)
#define ZSIPOS_SPI_SPCR_MSTR		(1 << 4)
#define ZSIPOS_SPI_SPCR_CPOL		(1 << 3)
#define ZSIPOS_SPI_SPCR_CPHA		(1 << 2)
#define ZSIPOS_SPI_SPCR_SPR			0x03

#define ZSIPOS_SPI_SPSR_SPIF		(1 << 7)
#define ZSIPOS_SPI_SPSR_WCOL		(1 << 6)
#define ZSIPOS_SPI_SPSR_WFFULL		(1 << 3)
#define ZSIPOS_SPI_SPSR_WFEMPTY		(1 << 2)
#define ZSIPOS_SPI_SPSR_RFFULL		(1 << 1)
#define ZSIPOS_SPI_SPSR_RFEMPTY		(1 << 0)

#define ZSIPOS_SPI_SPER_ESPR		0x03

struct zsipos_spi {
	struct spi_master	*master;
	void	__iomem		*base;
	void	__iomem		*reg_spsr;
	void	__iomem		*reg_spdr;
	int                 irq;
	struct completion   transferdone;
	unsigned int		max_speed;
	unsigned int		min_speed;
	unsigned int		last_speed;
	unsigned int		last_mode;
	unsigned int		last_bpw;
};

static u8 zsipos_spi_read(struct zsipos_spi* zsipos_spi, unsigned int reg) {
	return readl(zsipos_spi->base + reg);
}

static void zsipos_spi_write(struct zsipos_spi* zsipos_spi, unsigned int reg, u8 value) {
	writel(value, zsipos_spi->base + reg);
}

static int zsipos_spi_set_transfer_size(struct zsipos_spi *zsipos_spi, unsigned int size)
{
	if (size != 8) {
		printk("Bad transfer size: %d\n", size);
		return -EINVAL;
	}

	return 0;
}

static int zsipos_spi_get_clock_frequency(void)
{
	return 60000000;
}

static void zsipos_spi_set_baudrate_bits(u8* spcr, u8* sper, unsigned int speed)
{
	int i;

	for (i = 0; i < 11; i++) {
		if ((zsipos_spi_get_clock_frequency() >> (1+i)) <= speed) {
			break;
		}
	}

	/* The register values for some cases are weird... fix here */
	switch (i) {
	case 3:
		i = 5;
		break;
	case 4:
		i = 3;
		break;
	case 5:
		i = 4;
		break;
	}

	*spcr = (*spcr & ~ZSIPOS_SPI_SPCR_SPR ) | (i & ZSIPOS_SPI_SPCR_SPR);
	*sper = (*spcr & ~ZSIPOS_SPI_SPER_ESPR) | (i >> 2);
}

static void zsipos_spi_set_mode_bits(u8* spcr, int mode)
{
	if (mode & SPI_CPHA) *spcr |=  ZSIPOS_SPI_SPCR_CPHA;
	else 		         *spcr &= ~ZSIPOS_SPI_SPCR_CPHA;

	if (mode & SPI_CPOL) *spcr |=  ZSIPOS_SPI_SPCR_CPOL;
	else                 *spcr &= ~ZSIPOS_SPI_SPCR_CPOL;
}

/*
 * Called only when no transfer is active on the bus... this may
 * touch registers.
 */
static int zsipos_spi_setup_transfer(struct spi_device *spi, struct spi_transfer *t)
{
	struct zsipos_spi *zsipos_spi;
	unsigned int speed;
	unsigned int bits_per_word;
	u8 spcr, sper;

	zsipos_spi = spi_master_get_devdata(spi->master);

	if (t) {
		speed = t->speed_hz ? t->speed_hz : spi->max_speed_hz;
		bits_per_word = t->bits_per_word ? t->bits_per_word : spi->bits_per_word;
	} else {
		speed = spi->max_speed_hz;
		bits_per_word = spi->bits_per_word;
	}

	if (speed == zsipos_spi->last_speed && spi->mode == zsipos_spi->last_mode
			&& bits_per_word == zsipos_spi->last_bpw)
		return 0; /* nothing changed */

	zsipos_spi->last_speed = speed;
	zsipos_spi->last_mode  = spi->mode;
	zsipos_spi->last_bpw   = bits_per_word;

	spcr = zsipos_spi_read(zsipos_spi, ZSIPOS_SPI_REG_SPCR);
	sper = zsipos_spi_read(zsipos_spi, ZSIPOS_SPI_REG_SPER);

	zsipos_spi_set_baudrate_bits(&spcr, &sper, speed);
	zsipos_spi_set_mode_bits(&spcr, spi->mode);

	zsipos_spi_write(zsipos_spi, ZSIPOS_SPI_REG_SPCR, spcr);
	zsipos_spi_write(zsipos_spi, ZSIPOS_SPI_REG_SPER, sper);

	return zsipos_spi_set_transfer_size(zsipos_spi, bits_per_word);
}

static void zsipos_spi_set_cs(struct zsipos_spi *zsipos_spi, int mask)
{
	zsipos_spi_write(zsipos_spi, ZSIPOS_SPI_REG_SSR, mask);
}

static irqreturn_t zsipos_spi_irq(int irq, void *dev_id)
{
	struct zsipos_spi *zsipos_spi = dev_id;
	u8 stat = readl(zsipos_spi->reg_spsr);

	if (stat & ZSIPOS_SPI_SPSR_SPIF)
		complete(&zsipos_spi->transferdone);

	writel(stat, zsipos_spi->reg_spsr);

	return IRQ_HANDLED;
}

static void zsipos_spi_xfer_chunk(struct zsipos_spi *zsipos_spi, const u8 *txdata, u8 *rxdata, unsigned len)
{
	u32 __iomem *datareg = zsipos_spi->reg_spdr;
	u32 __iomem *statreg = zsipos_spi->reg_spsr;
	unsigned int i;
	u8 dummy;

	if (len >= MINIRQ) {
		zsipos_spi_write(zsipos_spi, ZSIPOS_SPI_REG_ICNT, len-1);
		reinit_completion(&zsipos_spi->transferdone);
		if (txdata)
			for (i = len; i; i--)
				writel(*txdata++, datareg);
		else
			for (i = len; i; i--)
				writel(ZSIPOS_SPI_FILL_BYTE, datareg);
		wait_for_completion(&zsipos_spi->transferdone);
		if (rxdata)
			for (i = len; i; i--)
				*rxdata++ = readl(datareg);
		else
			for (i = len; i; i--)
				readl(datareg);
	} else {
		zsipos_spi_write(zsipos_spi, ZSIPOS_SPI_REG_ICNT, FIFOSIZE-1);
		if (txdata)
			for (i = len; i; i--)
				writel(*txdata++, datareg);
		else
			for (i = len; i; i--)
				writel(ZSIPOS_SPI_FILL_BYTE, datareg);
		if (rxdata)
			for (i = len; i; i--) {
				while (readl(statreg) & ZSIPOS_SPI_SPSR_RFEMPTY)
					cond_resched();
				*rxdata++ = readl(datareg);
			}
		else
			for (i = len; i; i--) {
				while (readl(statreg) & ZSIPOS_SPI_SPSR_RFEMPTY)
					cond_resched();
				readl(datareg);
			}
	}

	if (!(readl(statreg) & ZSIPOS_SPI_SPSR_RFEMPTY))
		printk("fifo not empty: len=%d, tx=%d, rx=%d\n", len, txdata != 0, rxdata != 0);
}

static void zsipos_spi_xfer_fifo(struct zsipos_spi *zsipos_spi, const u8 *txdata, u8 *rxdata, unsigned len)
{
	unsigned int i, r = len % FIFOSIZE;

	for (i = 0; i < len / FIFOSIZE; i++) {
		zsipos_spi_xfer_chunk(zsipos_spi, txdata, rxdata, FIFOSIZE);
		if (txdata) txdata += FIFOSIZE;
		if (rxdata) rxdata += FIFOSIZE;
	}
	if (r)
		zsipos_spi_xfer_chunk(zsipos_spi, txdata, rxdata, r);
}

static unsigned int zsipos_spi_write_read(struct zsipos_spi *zsipos_spi, struct spi_transfer *xfer)
{
	zsipos_spi_xfer_fifo(zsipos_spi, xfer->tx_buf, xfer->rx_buf, xfer->len);
	return xfer->len;
}

static int zsipos_spi_transfer_one_message(struct spi_master *master, struct spi_message *m)
{
	struct zsipos_spi *zsipos_spi = spi_master_get_devdata(master);
	struct spi_device *spi = m->spi;
	struct spi_transfer *t = NULL;
	int par_override = 0;
	int status = 0;
	int cs_active = 0;

	/* Load defaults */
	status = zsipos_spi_setup_transfer(spi, NULL);

	if (status < 0)
		goto msg_done;

	list_for_each_entry(t, &m->transfers, transfer_list) {
		unsigned int bits_per_word = spi->bits_per_word;

		if (t->tx_buf == NULL && t->rx_buf == NULL && t->len) {
			dev_err(&spi->dev,
					"message rejected : "
					"invalid transfer data buffers\n");
			status = -EIO;
			goto msg_done;
		}

		if ((t != NULL) && t->bits_per_word)
			bits_per_word = t->bits_per_word;

		if ((bits_per_word != 8)) {
			dev_err(&spi->dev,
					"message rejected : "
					"invalid transfer bits_per_word (%d bits)\n",
					bits_per_word);
			status = -EIO;
			goto msg_done;
		}

		if (t->speed_hz && t->speed_hz < zsipos_spi->min_speed) {
			dev_err(&spi->dev,
					"message rejected : "
					"device min speed (%d Hz) exceeds "
					"required transfer speed (%d Hz)\n",
					zsipos_spi->min_speed, t->speed_hz);
			status = -EIO;
			goto msg_done;
		}

		if (par_override || t->speed_hz || t->bits_per_word) {
			par_override = 1;
			status = zsipos_spi_setup_transfer(spi, t);
			if (status < 0)
				break;
			if (!t->speed_hz && !t->bits_per_word)
				par_override = 0;
		}

		if (!cs_active) {
			zsipos_spi_set_cs(zsipos_spi, (1 << spi->chip_select));
			cs_active = 1;
		}

		if (t->len)
			m->actual_length += zsipos_spi_write_read(zsipos_spi, t);

		if (t->delay_usecs)
			udelay(t->delay_usecs);

		if (t->cs_change) {
			zsipos_spi_set_cs(zsipos_spi, 0);
			cs_active = 0;
		}

	}

msg_done:

	if (cs_active)
		zsipos_spi_set_cs(zsipos_spi, 0);

	if (m->context != (void*)-1) {
		m->status = status;
		spi_finalize_current_message(master);
	}

	return 0;
}

static int zsipos_spi_reset(struct zsipos_spi *zsipos_spi)
{
	/* Verify that the CS is deasserted */
	zsipos_spi_set_cs(zsipos_spi, 0);

	/* Disable controller */
	zsipos_spi_write(zsipos_spi, ZSIPOS_SPI_REG_SPCR, ZSIPOS_SPI_SPCR_MSTR);
	/* Enable controller */
	zsipos_spi_write(zsipos_spi, ZSIPOS_SPI_REG_SPCR, ZSIPOS_SPI_SPCR_MSTR | ZSIPOS_SPI_SPCR_SPEN | ZSIPOS_SPI_SPCR_SPIE);
	/* clear interrupt flag */
	zsipos_spi_write(zsipos_spi, ZSIPOS_SPI_REG_SPSR, ZSIPOS_SPI_SPSR_SPIF);

	return 0;
}

/*
 * The setup function configures the spi_device for communcation via
 * this controller.  This function may be called at any time and should
 * not touch registers.
 */
static int zsipos_spi_setup(struct spi_device *spi)
{
	struct zsipos_spi *zsipos_spi;

	zsipos_spi = spi_master_get_devdata(spi->master);

	if ((spi->max_speed_hz == 0)
			|| (spi->max_speed_hz > zsipos_spi->max_speed))
		spi->max_speed_hz = zsipos_spi->max_speed;

	if (spi->max_speed_hz < zsipos_spi->min_speed) {
		dev_err(&spi->dev, "setup: requested speed too low %d Hz\n",
				spi->max_speed_hz);
		return -EINVAL;
	}

	/*
	 * baudrate & width will be set by zsipos_spi_setup_transfer
	 */
	return 0;
}

static int zsipos_spi_probe(struct platform_device *pdev)
{
	struct spi_master *master;
	struct zsipos_spi *spi;
	struct resource *r;
	int status = 0;

	master = spi_alloc_master(&pdev->dev, sizeof *spi);
	if (master == NULL) {
		dev_dbg(&pdev->dev, "master allocation failed\n");
		return -ENOMEM;
	}

	if (pdev->id != -1)
		master->bus_num = pdev->id;

	master->bus_num = -1;

	/*
	 * we support only mode 0 for now, and no options...
	 * but we can support CPHA setting -- to be implemented
	 */
	master->mode_bits = SPI_MODE_3;

	master->setup = zsipos_spi_setup;
	master->transfer_one_message = zsipos_spi_transfer_one_message;
	master->num_chipselect = ZSIPOS_SPI_NUM_CHIPSELECTS;
#ifdef CONFIG_OF
	master->dev.of_node = pdev->dev.of_node;
#endif

	platform_set_drvdata(pdev, master);

	spi = spi_master_get_devdata(master);
	spi->master = master;

	init_completion(&spi->transferdone);


	spi->max_speed = zsipos_spi_get_clock_frequency() >> 1;
	spi->min_speed = zsipos_spi_get_clock_frequency() >> 12;

	spi->last_speed = -1;
	spi->last_mode  = -1;
	spi->last_bpw   = -1;

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
	spi->base = devm_ioremap_nocache(&pdev->dev, r->start,
			resource_size(r));
	spi->reg_spsr = spi->base + ZSIPOS_SPI_REG_SPSR;
	spi->reg_spdr = spi->base + ZSIPOS_SPI_REG_SPDR;

	spi->irq = platform_get_irq(pdev, 0);

	status = request_irq(spi->irq, zsipos_spi_irq, 0, DRIVER_NAME, spi);
	if (status < 0) {
		dev_err(&pdev->dev, DRIVER_NAME ": request irq %d failed "
				"(status = %d)\n", spi->irq, status);
		goto out;
	}

	zsipos_spi_reset(spi);

	status = spi_register_master(master);

	dev_info(&pdev->dev, "loaded\n");

	return status;

out:
	spi_master_put(master);
	return status;
}

static int zsipos_spi_remove(struct platform_device *pdev)
{
	struct spi_master *master;
	struct zsipos_spi *spi;

	master = platform_get_drvdata(pdev);
	spi = spi_master_get_devdata(master);

	spi_unregister_master(master);

	free_irq(spi->irq, spi);

	return 0;
}

static const struct of_device_id zsipos_spi_match[] = {
	{
		.compatible = "zsipos,spi",
	},
	{},
};
MODULE_DEVICE_TABLE(of, zsipos_spi_match);

static struct platform_driver zsipos_spi_driver = {
	.probe = zsipos_spi_probe,
	.remove = zsipos_spi_remove,
	.driver = {
		.name	= DRIVER_NAME,
		.owner	= THIS_MODULE,
		.of_match_table = zsipos_spi_match
	}
};
module_platform_driver(zsipos_spi_driver);

MODULE_DESCRIPTION("zsipos spi driver");
MODULE_AUTHOR("Stefan Adams");
MODULE_LICENSE("GPL");
