/*
 * zsipos_dmatest.c -- ZSIPOS DMA TEST driver
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

#define DRIVER_NAME "zsipos_dmatest"

#define LITEX_DMATEST_LENGTH_REG     LITEX_CSR_OFFSET(0)  // u32
#define LITEX_DMATEST_TXADR_REG      LITEX_CSR_OFFSET(4)  // u32
#define LITEX_DMATEST_RXADR_REG      LITEX_CSR_OFFSET(8)  // u32
#define LITEX_DMATEST_CONTROL_REG    LITEX_CSR_OFFSET(12) // u8
#define LITEX_DMATEST_STATUS_REG     LITEX_CSR_OFFSET(13) // u8

/*
 * WARNING! THIS A A VERY SPECIAL TEST MODULE.
 * NEVER INCLUDE IN A PROUCTION KERNEL!
 */

#define BIOSADR 0x10000000
#define SRAMADR 0x11000000
#define BBLADR  0x80000000
#define IOMADR  0x41000000 // abuse spim buffer
#define IOMLEN  0x1000

static void read_test(u32 srcadr, u32 len, void __iomem *csr_base, u8 __iomem *iomem)
{
	int i = 0;

	printk("DMA TEST ADR: %x\n", srcadr);
	litex_csr_writel(len, csr_base+LITEX_DMATEST_LENGTH_REG);
	litex_csr_writel(srcadr, csr_base+LITEX_DMATEST_TXADR_REG);
	litex_csr_writel(IOMADR, csr_base+LITEX_DMATEST_RXADR_REG);
	litex_csr_writeb(1, csr_base+LITEX_DMATEST_CONTROL_REG);
	while(litex_csr_readb(csr_base+LITEX_DMATEST_STATUS_REG))
		i++;
	printk("wait loops = %d\n", i);
	if (len > 8) len = 8;
	for(i = 0; i < len; i++) {
		printk("%d:%02x\n", i, iomem[i]);
		iomem[i] = 0;
	}
}

static void write_test(u32 dstadr, int len, void __iomem *csr_base, u8 __iomem *iomem, u8 pattern)
{
	int i;

	for(i = 0; i < len; i++)
		iomem[i] = pattern + i;
	litex_csr_writel(len, csr_base+LITEX_DMATEST_LENGTH_REG);
	litex_csr_writel(IOMADR, csr_base+LITEX_DMATEST_TXADR_REG);
	litex_csr_writel(dstadr, csr_base+LITEX_DMATEST_RXADR_REG);
	litex_csr_writeb(1, csr_base+LITEX_DMATEST_CONTROL_REG);
	while(litex_csr_readb(csr_base+LITEX_DMATEST_STATUS_REG))
		i++;
	for(i = 0; i < len; i++)
		iomem[i] = 0;
	flush_tlb_all();
}

static int zsipos_dmatest_probe(struct platform_device *pdev)
{
	void __iomem *csr_base;
	void __iomem *mem_base;
	struct resource *r;
	int status = 0;

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
	csr_base = devm_ioremap_nocache(&pdev->dev, r->start,
			resource_size(r));
	if (IS_ERR(csr_base)) {
		status = PTR_ERR(csr_base);
		goto out;
	}

	if (!devm_request_mem_region(&pdev->dev, IOMADR, IOMLEN, dev_name(&pdev->dev))) {
		status = -EBUSY;
		goto out;
	}
	mem_base = devm_ioremap_nocache(&pdev->dev, IOMADR, IOMLEN);
	if (IS_ERR(mem_base)) {
		status = PTR_ERR(mem_base);
		goto out;
	}

	printk("ZSIPOS DMA TEST\n");

	read_test(BBLADR, 1024, csr_base, mem_base);
	read_test(BIOSADR, 1024, csr_base, mem_base);
	write_test(BBLADR+(1<<25), 1024, csr_base, mem_base, 0x80);
	write_test(SRAMADR, 1024, csr_base, mem_base, 0x10);
	read_test(BBLADR+(1<<25), 1024, csr_base, mem_base);
	read_test(SRAMADR, 1024, csr_base, mem_base);

out:
	return status;
}

static int zsipos_dmatest_remove(struct platform_device *pdev)
{
	return 0;
}

static const struct of_device_id zsipos_dmatest_match[] = {
	{ .compatible = "zsipos,dmatest" },
	{},
};
MODULE_DEVICE_TABLE(of, zsipos_dmatest_match);

static struct platform_driver zsipos_dmatest_driver = {
	.probe = zsipos_dmatest_probe,
	.remove = zsipos_dmatest_remove,
	.driver = {
		.name	= DRIVER_NAME,
		.owner	= THIS_MODULE,
		.of_match_table = zsipos_dmatest_match
	}
};
module_platform_driver(zsipos_dmatest_driver);

MODULE_DESCRIPTION("zsipos dmatest driver");
MODULE_AUTHOR("Stefan Adams");
MODULE_LICENSE("GPL");
