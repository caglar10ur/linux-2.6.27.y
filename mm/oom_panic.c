/* 
 * Just panic() instead of the default behavior of selecting processes
 * for death.
 *
 * Based on
 * Modular OOM handlers for 2.6.4 (C) 2003,2004 Tvrtko A. Ursulin
 * and
 * linux/mm/oom_kill.c (C) 1998,2000 Rik van Riel.
 *
 * Mark Huang <mlhuang@cs.princeton.edu>
 *
 * $Id: oom_panic.c,v 1.1 2004/10/01 17:54:48 mlhuang Exp $
 */

#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/swap.h>

/**
 * out_of_memory - is the system out of memory?
 */
void out_of_memory(int gfp_mask)
{
	/*
	 * oom_lock protects out_of_memory()'s static variables.
	 * It's a global lock; this is not performance-critical.
	 */
	static spinlock_t oom_lock = SPIN_LOCK_UNLOCKED;
	static unsigned long count;

	spin_lock(&oom_lock);

	/*
	 * If we have gotten only a few failures,
	 * we're not really oom. 
	 */
	if (++count < 10)
		goto out_unlock;

	/*
	 * Ok, really out of memory. Panic.
	 */

	printk("oom-killer: gfp_mask=0x%x\n", gfp_mask);
	show_free_areas();

	panic("Out Of Memory");

out_unlock:
	spin_unlock(&oom_lock);
}
