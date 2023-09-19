#include <linux/bpf.h>
#include <linux/bpfbox.h>

void __bpfbox *__percpu_array_map_lookup_elem(struct bpf_array_inner __bpfbox *inner,
					    void __bpfbox *key)
{
	u32 index = *(u32 *)(fast_bpf_unbox_ptr(key));
	int i = raw_smp_processor_id();
	struct bpf_array_inner *safe_inner = fast_bpf_unbox_ptr(inner);
	void __bpfbox *pptr = safe_inner->pptrs[i];
	if (unlikely(index >= safe_inner->max_entries))
		return NULL;
	return pptr + index*safe_inner->elem_size;
}
