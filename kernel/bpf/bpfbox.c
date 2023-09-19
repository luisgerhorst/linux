#include <linux/bpf.h>
#include <linux/bpfbox.h>
#include <linux/vmalloc.h>
#include <linux/cpumask.h>
#include <linux/atomic/atomic-instrumented.h>

void *bpfbox_alloc(unsigned long size)
{
	const gfp_t gfp = (__GFP_NOWARN | __GFP_ZERO | __GFP_ACCOUNT
			   | GFP_KERNEL | __GFP_RETRY_MAYFAIL);
	return __vmalloc_node_range(size, PAGE_SIZE, BPFBOX_START, BPFBOX_END,
				    gfp, PAGE_KERNEL, 0, NUMA_NO_NODE,
				    __builtin_return_address(0));
}

void bpfbox_free(void *p)
{
	vfree(p);
}

DEFINE_PER_CPU(struct bpfbox_scratch_region, bpfbox_scratch_region);

#define BPF_SCRATCH_SIZE_PAGE 512

int __init init_bpfbox_stack(void)
{
	int i;
	for (i = 0; i < nr_cpu_ids; i++) {
		struct bpfbox_scratch_region *region = per_cpu_ptr(&bpfbox_scratch_region, i);
		long size = BPF_SCRATCH_SIZE_PAGE * PAGE_SIZE;
		region->start = bpfbox_alloc(size);
		region->size = size;
	}
	return 0;
}
device_initcall(init_bpfbox_stack);

unsigned int open_bpf_scratch(int size)
{
	struct bpfbox_scratch_region *region;
	int cur;
	region = raw_cpu_ptr(&bpfbox_scratch_region);
	cur = local_add_return(size, &region->sp);
	return (unsigned int)((unsigned long)region->start - (unsigned long)BPFBOX_START + cur);
}

void close_bpf_scratch(int size)
{
	struct bpfbox_scratch_region *region = this_cpu_ptr(&bpfbox_scratch_region);
	local_sub(size, &region->sp);
}
