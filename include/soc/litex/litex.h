/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_LITEX_H
#define _LINUX_LITEX_H

#include <linux/io.h>
#include <linux/types.h>
#include <linux/compiler_types.h>

#ifdef _LP64
#define LITEX_REG_SIZE             0x8	// alignment of csr registers
#define LITEX_BUS_SIZE             0x4	// alignment of wishbone bus
#else
#define LITEX_REG_SIZE             0x4
#define LITEX_BUS_SIZE             0x4
#endif

#define LITEX_BUS_OFFSET(off)      ((off)*LITEX_BUS_SIZE)
#define LITEX_CSR_OFFSET(off)      ((off)*LITEX_REG_SIZE)

#define LITEX_SUBREG_SIZE          0x1
#define LITEX_SUBREG_SIZE_BIT      (LITEX_SUBREG_SIZE * 8)

#ifdef __LITTLE_ENDIAN
# define LITEX_READ_REG(addr)                  ioread32(addr)
# define LITEX_READ_REG_OFF(addr, off)         ioread32(addr + off)
# define LITEX_WRITE_REG(val, addr)            iowrite32(val, addr)
# define LITEX_WRITE_REG_OFF(val, addr, off)   iowrite32(val, addr + off)
#else
# define LITEX_READ_REG(addr)                  ioread32be(addr)
# define LITEX_READ_REG_OFF(addr, off)         ioread32be(addr + off)
# define LITEX_WRITE_REG(val, addr)            iowrite32be(val, addr)
# define LITEX_WRITE_REG_OFF(val, addr, off)   iowrite32be(val, addr + off)
#endif

/* Helper functions for manipulating LiteX registers */

static inline void litex_set_reg(void __iomem *reg, u32 reg_size, u32 val)
{
	u32 shifted_data, shift, i;

	for (i = 0; i < reg_size; ++i) {
		shift = ((reg_size - i - 1) * LITEX_SUBREG_SIZE_BIT);
		shifted_data = val >> shift;
		LITEX_WRITE_REG(shifted_data, reg + (LITEX_REG_SIZE * i));
	}
}

static inline u32 litex_get_reg(void __iomem *reg, u32 reg_size)
{
	u32 shifted_data, shift, i;
	u32 result = 0;

	for (i = 0; i < reg_size; ++i) {
		shifted_data = LITEX_READ_REG(reg + (LITEX_REG_SIZE * i));
		shift = ((reg_size - i - 1) * LITEX_SUBREG_SIZE_BIT);
		result |= (shifted_data << shift);
	}

	return result;
}

static inline void litex_csr_writeb(u8 val, void __iomem *reg)
{
	LITEX_WRITE_REG(val, reg);
}

static inline void litex_csr_writew(u16 val, void __iomem *reg)
{
	LITEX_WRITE_REG(val >> 8, reg                      );
	LITEX_WRITE_REG(val     , reg + LITEX_CSR_OFFSET(1));
}

static inline void litex_csr_writel(u32 val, void __iomem *reg)
{
	LITEX_WRITE_REG(val >> 24, reg                      );
	LITEX_WRITE_REG(val >> 16, reg + LITEX_CSR_OFFSET(1));
	LITEX_WRITE_REG(val >>  8, reg + LITEX_CSR_OFFSET(2));
	LITEX_WRITE_REG(val      , reg + LITEX_CSR_OFFSET(3));
}

static inline u8 litex_csr_readb(void __iomem *reg)
{
	return LITEX_READ_REG(reg);
}

static inline u16 litex_csr_readw(void __iomem *reg)
{
	return (LITEX_READ_REG(reg) << 8) | LITEX_READ_REG(reg + LITEX_CSR_OFFSET(1));
}

static inline u32 litex_csr_readl(void __iomem * reg)
{
	return  (LITEX_READ_REG(reg)                       << 24) |
			(LITEX_READ_REG(reg + LITEX_CSR_OFFSET(1)) << 16) |
			(LITEX_READ_REG(reg + LITEX_CSR_OFFSET(2)) <<  8) |
			(LITEX_READ_REG(reg + LITEX_CSR_OFFSET(3))      );
}

#endif /* _LINUX_LITEX_H */
