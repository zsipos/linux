/*
 * Simple synchronous userspace interface to zsipos_aes
 *
 * Copyright (C) 2019 Stefan Adams
 *	Stefan Adams <stefan.adams@vipcomag.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/device.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <soc/litex/litex.h>

#define DRVNAME	"zsipos_aes"

static struct class  *zsipos_aes_class;
static struct device *g_dev;
static dev_t          g_devt;
static u32 			  g_mem_base;
static u32			  g_mem_size;
static volatile u32  *g_base_addr;
static bool 		  g_open = false;

static DEFINE_MUTEX(g_open_lock);

static int zsipos_aes_mmap(struct file *filp, struct vm_area_struct *vma)
{
	unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
	size_t size = vma->vm_end - vma->vm_start;

	if (offset != g_mem_base) {
		dev_err(g_dev, "invalid mmap request\n");
	}

    vma->vm_flags |= VM_IO;

	if (remap_pfn_range(vma,
			    vma->vm_start,
			    vma->vm_pgoff,
			    size,
			    vma->vm_page_prot)) {
		dev_err(g_dev, "remap_pfn_range() failed\n");
		return -EAGAIN;
	}

	return 0;
}

static int zsipos_aes_open(struct inode *inode, struct file *filp)
{
	mutex_lock(&g_open_lock);
	if (g_open) {
		mutex_unlock(&g_open_lock);
		return -EAGAIN;
	}
	g_open = true;
	mutex_unlock(&g_open_lock);
	return 0;
}

static int zsipos_aes_release(struct inode *inode, struct file *filp)
{
	mutex_lock(&g_open_lock);
	*g_base_addr = 0;
	g_open = false;
	mutex_unlock(&g_open_lock);
	return 0;
}

static const struct file_operations zsipos_aes_fops = {
		.owner			= THIS_MODULE,
		.mmap           = zsipos_aes_mmap,
		.open           = zsipos_aes_open,
		.release        = zsipos_aes_release,
		.llseek         = no_llseek,
};

/*-------------------------------------------------------------------------*/


static int zsipos_aes_probe(struct platform_device *pdev)
{
	int              status;
	struct resource *res;

	/* register / request resources */
	status = register_chrdev(0, DRVNAME "", &zsipos_aes_fops);
	if (status < 0) {
		return status;
	}
	g_devt = MKDEV(status, 0);
	status = 0;

	zsipos_aes_class = class_create(THIS_MODULE, DRVNAME);
	if (IS_ERR(zsipos_aes_class)) {
		status = PTR_ERR(zsipos_aes_class);
		goto err_class;
	}

	g_dev = device_create(zsipos_aes_class, NULL, g_devt,
			    NULL, DRVNAME);
	if (IS_ERR(g_dev)) {
		status = PTR_ERR(g_dev);
		goto err_device;
	}

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	g_mem_base = res->start;
	g_mem_size = res->end - res->start + 1;

	if (request_mem_region(g_mem_base, g_mem_size, DRVNAME) == NULL) {
		dev_err(g_dev, "can not request memory region\n");
		status = -ENXIO;
		goto err_device;
	}

	g_base_addr = ioremap_nocache(g_mem_base, g_mem_size);
	if (IS_ERR((void*)g_base_addr)) {
		dev_err(g_dev, "can not map memory region\n");
		status = -ENXIO;
		goto err_ioremap;
	}

	dev_info(g_dev, "loaded\n");

	return status;

err_ioremap:
	release_mem_region(g_mem_base, g_mem_size);
err_device:
	class_destroy(zsipos_aes_class);
err_class:
	unregister_chrdev(MAJOR(g_devt), DRVNAME);

	return status;
}

static int zsipos_aes_remove(struct platform_device *pdev)
{
	iounmap((void*)g_base_addr);
	release_mem_region(g_mem_base, g_mem_size);
	device_destroy(zsipos_aes_class, g_devt);
	class_destroy(zsipos_aes_class);
	unregister_chrdev(MAJOR(g_devt), DRVNAME);
	return 0;
}

static const struct of_device_id zsipos_aes_dt_match[] = {
	{ .compatible = "zsipos,aes" },
	{},
};
MODULE_DEVICE_TABLE(of, zsipos_aes_dt_match);

static struct platform_driver zsipos_aes_driver = {
	.probe  = zsipos_aes_probe,
	.remove = zsipos_aes_remove,
	.driver = {
		.name = DRVNAME,
		.of_match_table = zsipos_aes_dt_match,
	},
};
module_platform_driver(zsipos_aes_driver);

MODULE_AUTHOR("Stefan Adams, <stefan.adams@vipcomag.de>");
MODULE_DESCRIPTION("mmap interface for secworks aes crypto core");
MODULE_LICENSE("GPL");
