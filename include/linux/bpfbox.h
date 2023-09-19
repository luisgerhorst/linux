#ifndef _LINUX_BPFBOX_H
#define _LINUX_BPFBOX_H

#include <linux/vmalloc.h>
#include <linux/types.h>
#include <linux/percpu-defs.h>
#include <asm/local.h>

void *bpfbox_alloc(unsigned long size);
void bpfbox_free(void *p);

#define bpf_unbox_ptr(p) \
({									\
	(typeof(*(p)) __kernel __force *)(BPFBOX_START + ((unsigned long)(p) & 0xffffffff)); \
})

static inline void *fast_bpf_unbox_ptr(void __bpfbox *p)
{
	void *ret;
	p = (void *)((unsigned long) p & 0xffffffff);
	asm ("lea (%1,%%r12), %0"
		: "=r" (ret)
		: "r" (p));
	return ret;
}

static inline void __bpfbox *bpf_box_ptr(void *ptr)
{
	return (__bpfbox void*) (ptr - BPFBOX_START);
}

struct bpfbox_scratch_region {
	void *start;
	int size;
	local_t sp;
};

DECLARE_PER_CPU(struct bpfbox_scratch_region, bpfbox_scratch_region);

int init_bpfbox_stack(void);
unsigned int open_bpf_scratch(int size);
void close_bpf_scratch(int size);

#endif
