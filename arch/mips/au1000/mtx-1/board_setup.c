/*
 *
 * BRIEF MODULE DESCRIPTION
 *	4G Systems MTX-1 board setup.
 *
 * Copyright 2003, 2008 MontaVista Software Inc.
 * Author: MontaVista Software, Inc. <source@mvista.com>
 *         Bruno Randolf <bruno.randolf@4g-systems.biz>
 *
 *  This program is free software; you can redistribute  it and/or modify it
 *  under  the terms of  the GNU General  Public License as published by the
 *  Free Software Foundation;  either version 2 of the  License, or (at your
 *  option) any later version.
 *
 *  THIS  SOFTWARE  IS PROVIDED   ``AS  IS'' AND   ANY  EXPRESS OR IMPLIED
 *  WARRANTIES,   INCLUDING, BUT NOT  LIMITED  TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN
 *  NO  EVENT  SHALL   THE AUTHOR  BE    LIABLE FOR ANY   DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 *  NOT LIMITED   TO, PROCUREMENT OF  SUBSTITUTE GOODS  OR SERVICES; LOSS OF
 *  USE, DATA,  OR PROFITS; OR  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 *  ANY THEORY OF LIABILITY, WHETHER IN  CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 *  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  You should have received a copy of the  GNU General Public License along
 *  with this program; if not, write  to the Free Software Foundation, Inc.,
 *  675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/init.h>

#include <asm/mach-au1x00/au1000.h>

extern int (*board_pci_idsel)(unsigned int devsel, int assert);
int mtx1_pci_idsel(unsigned int devsel, int assert);

void board_reset(void)
{
	/* Hit BCSR.SYSTEM_CONTROL[SW_RST] */
	au_writel(0x00000000, 0xAE00001C);
}

void __init board_setup(void)
{
#if defined(CONFIG_USB_OHCI_HCD) || defined(CONFIG_USB_OHCI_HCD_MODULE)
	/* Enable USB power switch */
	au_writel(au_readl(GPIO2_DIR) | 0x10, GPIO2_DIR);
	au_writel(0x100000, GPIO2_OUTPUT);
#endif /* defined(CONFIG_USB_OHCI_HCD) || defined(CONFIG_USB_OHCI_HCD_MODULE) */

#ifdef CONFIG_PCI
#if defined(__MIPSEB__)
	au_writel(0xf | (2 << 6) | (1 << 4), Au1500_PCI_CFG);
#else
	au_writel(0xf, Au1500_PCI_CFG);
#endif
#endif

	/* Initialize sys_pinfunc */
	au_writel(SYS_PF_NI2, SYS_PINFUNC);

	/* Initialize GPIO */
	au_writel(0xFFFFFFFF, SYS_TRIOUTCLR);
	au_writel(0x00000001, SYS_OUTPUTCLR); /* set M66EN (PCI 66MHz) to OFF */
	au_writel(0x00000008, SYS_OUTPUTSET); /* set PCI CLKRUN# to OFF */
	au_writel(0x00000002, SYS_OUTPUTSET); /* set EXT_IO3 ON */
	au_writel(0x00000020, SYS_OUTPUTCLR); /* set eth PHY TX_ER to OFF */

	/* Enable LED and set it to green */
	au_writel(au_readl(GPIO2_DIR) | 0x1800, GPIO2_DIR);
	au_writel(0x18000800, GPIO2_OUTPUT);

	board_pci_idsel = mtx1_pci_idsel;

	printk(KERN_INFO "4G Systems MTX-1 Board\n");
}

int
mtx1_pci_idsel(unsigned int devsel, int assert)
{
#define MTX_IDSEL_ONLY_0_AND_3 0
#if MTX_IDSEL_ONLY_0_AND_3
	if (devsel != 0 && devsel != 3) {
		printk(KERN_ERR "*** not 0 or 3\n");
		return 0;
	}
#endif

	if (assert && devsel != 0)
		/* Suppress signal to Cardbus */
		au_writel(0x00000002, SYS_OUTPUTCLR); /* set EXT_IO3 OFF */
	else
		au_writel(0x00000002, SYS_OUTPUTSET); /* set EXT_IO3 ON */
	au_sync_udelay(1);
	return 1;
}

