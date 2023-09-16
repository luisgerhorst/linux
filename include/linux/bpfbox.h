#ifndef _LINUX_BPFBOX_H
#define _LINUX_BPFBOX_H

#include <linux/types.h>
#include <linux/percpu-defs.h>

void *bpfbox_alloc(unsigned long size);
void bpfbox_free(void *p);

struct bpfbox_scratch_region {
	void *start;
	int size;
	atomic_t sp;
};

DECLARE_PER_CPU(struct bpfbox_scratch_region, bpfbox_scratch_region);

int init_bpfbox_stack(void);
unsigned int open_bpf_scratch(int size);
void close_bpf_scratch(int size);

#endif
