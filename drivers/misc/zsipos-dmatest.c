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

#include <linux/dma-mapping.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>

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

#define SRAMADR 0x11000000
#define SRAMLEN 0x8000
#define TSTLEN  8192

static void dma_copy(void __iomem *csr_base, u32 srcadr, u32 dstadr, int len)
{
	int n = 0;

	printk("DMA COPY %x --> %x, %d", srcadr, dstadr, len);
	litex_csr_writel(len, csr_base+LITEX_DMATEST_LENGTH_REG);
	litex_csr_writel(srcadr, csr_base+LITEX_DMATEST_TXADR_REG);
	litex_csr_writel(dstadr, csr_base+LITEX_DMATEST_RXADR_REG);
	litex_csr_writeb(1, csr_base+LITEX_DMATEST_CONTROL_REG);
	while(litex_csr_readb(csr_base+LITEX_DMATEST_STATUS_REG))
		n++;
}

static int zsipos_dmatest_probe(struct platform_device *pdev)
{
	void __iomem *csr_base;
	void __iomem *sram_base;
	void __iomem *dma_base;
	dma_addr_t    dma_addr;
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

	if (!devm_request_mem_region(&pdev->dev, SRAMADR, SRAMLEN, dev_name(&pdev->dev))) {
		status = -EBUSY;
		goto out;
	}
	sram_base = devm_ioremap_nocache(&pdev->dev, SRAMADR, SRAMLEN);
	if (IS_ERR(sram_base)) {
		status = PTR_ERR(sram_base);
		goto out;
	}

	dma_base = dma_alloc_coherent(&pdev->dev, TSTLEN, &dma_addr, GFP_KERNEL);

	printk("\nZSIPOS DMA TEST\n");

	printk("test-1: copy IOMEM to IOMEM");
	strcpy(sram_base, "1-Hello World!");
	printk("write=%s\n", (char*)sram_base);
	dma_copy(csr_base, SRAMADR, SRAMADR+1024, 32);
	strcpy(sram_base, "1-Bad Copy-1");
	dma_copy(csr_base, SRAMADR+1024, SRAMADR, 32);
	printk("read=%s\n\n", (char*)sram_base);

	printk("test-2: copy IOMEM to DMA to IOMEM");
	strcpy(sram_base, "2-Hello World!");
	printk("write=%s\n", (char*)sram_base);
	dma_copy(csr_base, SRAMADR, dma_addr, TSTLEN);
	strcpy(sram_base, "2-Bad Copy-3");
	dma_copy(csr_base, dma_addr, SRAMADR, TSTLEN);
	printk("read=%s\n\n", (char*)sram_base);

	printk("test-3: copy IOMEM to DMA");
	strcpy(sram_base, "3-Hello World!");
	printk("write=%s\n", (char*)sram_base);
	strcpy(dma_base, "3-Bad Copy-3");
	dma_copy(csr_base, SRAMADR, dma_addr, TSTLEN);
	printk("read=%s\n\n", (char*)dma_base);

	printk("test-4: copy DMA to IOMEM");
	strcpy(dma_base, "4-Hello, World!");
	printk("write=%s\n", (char*)dma_base);
	strcpy(sram_base, "4-Bad Copy-4");
	dma_copy(csr_base, dma_addr, SRAMADR, TSTLEN);
	printk("read=%s\n\n", (char*)sram_base);

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
