#include "linux/container_of.h"
#include <linux/bpf.h>
#include <linux/bpfbox.h>

void __bpfbox *__percpu_array_map_lookup_elem(struct bpf_map_inner __bpfbox *inner,
					    void __bpfbox *key)
{
	u32 index = *(u32 *)(fast_bpf_unbox_ptr(key));
	int i = raw_smp_processor_id();
	struct bpf_map_inner *safe_inner = fast_bpf_unbox_ptr(inner);
	struct bpf_array_inner *array_inner =
		container_of(safe_inner, struct bpf_array_inner, map_inner);
	void __bpfbox *pptr = array_inner->pptrs[i];
	if (unlikely(index >= safe_inner->max_entries))
		return NULL;
	return pptr + index*safe_inner->elem_size;
}
