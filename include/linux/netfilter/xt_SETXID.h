#ifndef _XT_SETXID_H_target
#define _XT_SETXID_H_target

/* Version 1 */
enum {
	XT_SET_PACKET_XID=0
};

struct xt_setxid_target_info_v1 {
	unsigned long mark;
	u_int8_t mode;
};

#endif /*_XT_SETXID_H_target*/
