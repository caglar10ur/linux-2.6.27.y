#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/checksum.h>
#include <linux/vs_network.h>

#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_SETXID.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("");
MODULE_DESCRIPTION("");
MODULE_ALIAS("ipt_SETXID");

static unsigned int
target_v1(struct sk_buff **pskb,
	  const struct net_device *in,
	  const struct net_device *out,
	  unsigned int hooknum,
	  const struct xt_target *target,
	  const void *targinfo)
{
	const struct xt_setxid_target_info_v1 *setxidinfo = targinfo;

	switch (setxidinfo->mode) {
	case XT_SET_PACKET_XID:
		 (*pskb)->skb_tag = setxidinfo->mark;
		break;
	}
	return XT_CONTINUE;
}


static int
checkentry_v1(const char *tablename,
	      const void *entry,
	      const struct xt_target *target,
	      void *targinfo,
	      unsigned int hook_mask)
{
	struct xt_setxid_target_info_v1 *setxidinfo = targinfo;

	if (setxidinfo->mode != XT_SET_PACKET_XID) {
		printk(KERN_WARNING "SETXID: unknown mode %u\n",
		       setxidinfo->mode);
		return 0;
	}

	return 1;
}

static struct xt_target xt_setxid_target[] = {
	{
		.name		= "SETXID",
		.family		= AF_INET,
		.revision	= 1,
		.checkentry	= checkentry_v1,
		.target		= target_v1,
		.targetsize	= sizeof(struct xt_setxid_target_info_v1),
		.table		= "mangle",
		.me		= THIS_MODULE,
	}
};

static int __init init(void)
{
	int err;

	err = xt_register_targets(xt_setxid_target, ARRAY_SIZE(xt_setxid_target));
	return err;
}

static void __exit fini(void)
{
	xt_unregister_targets(xt_setxid_target, ARRAY_SIZE(xt_setxid_target));
}

module_init(init);
module_exit(fini);
