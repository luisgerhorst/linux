#include <linux/bpf.h>
#include <linux/bpfbox.h>
#include <linux/vmalloc.h>
#include <linux/cpumask.h>
#include <linux/atomic/atomic-instrumented.h>

void *bpfbox_alloc(unsigned long size)
{
	const gfp_t gfp = (__GFP_NOWARN | __GFP_ZERO | __GFP_ACCOUNT
			   | GFP_KERNEL | __GFP_RETRY_MAYFAIL);
	return __vmalloc_node_range(size, PAGE_SIZE, BPFBOX_START + PAGE_SIZE, BPFBOX_END,
				    gfp, PAGE_KERNEL, 0, NUMA_NO_NODE,
				    __builtin_return_address(0));
}

void bpfbox_free(void *p)
{
	vfree(p);
}

void __bpfbox **bpfbox_alloc_pcpu(unsigned long size)
{
	int nrcpu = nr_cpu_ids, i, alloc_size, offset;
	void __bpfbox **base;
	void *stuff;
	size = roundup(size, 64);
	alloc_size = size * nrcpu;
	offset = roundup(nrcpu * sizeof(void *), 64);
	alloc_size += offset;
	base = bpfbox_alloc(alloc_size);
	if (!base) {
		goto err;
	}
	stuff = base + offset;
	for (i = 0; i < nrcpu; i++) {
		base[i] = bpf_box_ptr(stuff + i*size);
	}
	return base;
err:
	return NULL;
}

void bpfbox_free_pcpu(void *p)
{
	bpfbox_free(p);
}

DEFINE_PER_CPU(struct bpfbox_scratch_region, bpfbox_scratch_region);
EXPORT_PER_CPU_SYMBOL(bpfbox_scratch_region);

#define BPF_SCRATCH_SIZE_PAGE 70

int __init init_bpfbox_stack(void)
{
	int i;
	for (i = 0; i < nr_cpu_ids; i++) {
		struct bpfbox_scratch_region *region = per_cpu_ptr(&bpfbox_scratch_region, i);
		long size = BPF_SCRATCH_SIZE_PAGE * PAGE_SIZE;
		region->start = bpfbox_alloc(size) - BPFBOX_START;
		region->size = size;
		local_set(&region->sp, (unsigned long)region->start + size - PAGE_SIZE);
	}
	return 0;
}
device_initcall(init_bpfbox_stack);

