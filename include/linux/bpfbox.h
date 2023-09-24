#ifndef _LINUX_BPFBOX_H
#define _LINUX_BPFBOX_H

#include <linux/vmalloc.h>
#include <linux/types.h>
#include <linux/percpu-defs.h>
#include <asm/local.h>

void *bpfbox_alloc(unsigned long size);
void bpfbox_free(void *p);
void __bpfbox **bpfbox_alloc_pcpu(unsigned long size);
void bpfbox_free_pcpu(void __bpfbox **p);

#ifdef CONFIG_DEBUG_KERNEL
#define BPFBOX_CHECK_VALID(p)
#else
#define BPFBOX_CHECK_VALID(p)
#endif

#define bpf_unbox_ptr(p) \
({			 \
	BPFBOX_CHECK_VALID((p));				\
	(typeof(*(p)) __kernel __force *)(BPFBOX_START + ((unsigned long)(p) & 0xffffffff)); \
})

static inline void *fast_bpf_unbox_ptr(void __bpfbox *p)
{
	BPFBOX_CHECK_VALID(p);
	p = (void __bpfbox *)((unsigned long) p & 0xffffffff);
	asm ("add %%r12, %0"
		: "=r" (p));
	return (void __kernel __force *) p;
}

#define bpf_unbox_or_null_ptr(p) \
({ \
	(p == NULL) ? NULL : bpf_unbox_ptr(p); \
})

static inline void __bpfbox *bpf_box_ptr(void *ptr)
{
	void __bpfbox *p = (void __bpfbox *)(ptr - BPFBOX_START);
	BPFBOX_CHECK_VALID(p);
	return p;
}

static inline void __bpfbox *bpf_box_or_null_ptr(void *ptr)
{
	if (ptr == NULL)
		return NULL;
	else
		return bpf_box_ptr(ptr);
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
