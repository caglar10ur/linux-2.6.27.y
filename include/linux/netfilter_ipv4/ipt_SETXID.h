#ifndef _IPT_SETXID_H_target
#define _IPT_SETXID_H_target

/* Backwards compatibility for old userspace */

#include <linux/netfilter/xt_SETXID.h>

/* Version 1 */
#define IPT_SET_PACKET_XID	XT_SET_PACKET_XID

#define ipt_setxid_target_info_v1 xt_setxid_target_info_v1

#endif /*_IPT_SETXID_H_target*/
