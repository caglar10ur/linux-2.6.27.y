#ifndef __ARRAYS_H__
#define __ARRAYS_H__
#include <linux/list.h>

#define SAMPLING_METHOD_DEFAULT 0
#define SAMPLING_METHOD_LOG 1

/* Every probe has an array handler */

/* XXX - Optimize this structure */

extern void (*rec_event)(void *,unsigned int);
struct array_handler {
	struct list_head link;
	unsigned int (*hash_func)(void *);
	unsigned int (*sampling_func)(void *,int,void *);
	unsigned short size;
	unsigned int threshold;
	unsigned char **expcount;
	unsigned int sampling_method;
	unsigned int **arrays;
	unsigned int arraysize;
	unsigned int num_samples[2];
	void **epoch_samples; /* size-sized lists of samples */
	unsigned int (*serialize)(void *, void *);
	unsigned char code[5];
};

struct event {
	struct list_head link;
	void *event_data;
	unsigned int count;
	unsigned int event_type;
	struct task_struct *task;
};
#endif
