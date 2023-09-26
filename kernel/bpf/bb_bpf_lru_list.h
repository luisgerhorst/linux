/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2016 Facebook
 */
#ifndef __BB_BPF_LRU_LIST_H_
#define __BB_BPF_LRU_LIST_H_

#include <linux/bpfbox.h>
#include <linux/cache.h>
#include <linux/spinlock_types.h>

#define NR_BPF_LRU_LIST_T	(3)
#define NR_BPF_LRU_LIST_COUNT	(2)
#define NR_BPF_LRU_LOCAL_LIST_T (2)
#define BPF_LOCAL_LIST_T_OFFSET NR_BPF_LRU_LIST_T

enum bpf_lru_list_type {
	BPF_LRU_LIST_T_ACTIVE,
	BPF_LRU_LIST_T_INACTIVE,
	BPF_LRU_LIST_T_FREE,
	BPF_LRU_LOCAL_LIST_T_FREE,
	BPF_LRU_LOCAL_LIST_T_PENDING,
};

struct bb_list_head {
	struct bb_list_head __bpfbox *next, *prev;
};

#undef list_entry
#define list_entry(ptr, type, member) \
	box_container_of(ptr, type, member)

#undef list_last_entry
#define list_last_entry(ptr, type, member)	\
	list_entry((*unbox(ptr)).prev, type, member)

#undef list_first_entry
#define list_first_entry(ptr, type, member) \
	list_entry((*unbox(ptr)).next, type, member)

#undef list_next_entry
#define list_next_entry(pos, member) \
	list_entry((*unbox(&(pos)->member)).next, typeof(*(pos)), member)

#undef list_prev_entry
#define list_prev_entry(pos, member) \
	list_entry((*unbox(&(pos)->member)).prev, typeof(*(pos)), member)

#undef list_entry_is_head
#define list_entry_is_head(pos, head, member)				\
	(&pos->member == (head))

#undef list_for_each_entry_safe
#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_first_entry(head, typeof(*pos), member),	\
		n = list_next_entry(pos, member);			\
	     !list_entry_is_head(pos, head, member); 			\
	     pos = n, n = list_next_entry(n, member))

#undef list_for_each_entry_safe_reverse
#define list_for_each_entry_safe_reverse(pos, n, head, member)		\
	for (pos = list_last_entry(head, typeof(*pos), member),		\
		n = list_prev_entry(pos, member);			\
	     !list_entry_is_head(pos, head, member); 			\
	     pos = n, n = list_prev_entry(n, member))

#undef list_first_entry_or_null
#define list_first_entry_or_null(ptr, type, member) ({ \
	struct bb_list_head __bpfbox *head__ = (ptr); \
	struct bb_list_head __bpfbox *pos__ = BB_READ_ONCE(head__->next); \
	pos__ != head__ ? list_entry(pos__, type, member) : NULL; \
})

struct bb_bpf_lru_node {
	struct bb_list_head list;
	u16 cpu;
	u8 type;
	u8 ref;
};

struct bb_bpf_lru_list {
	struct bb_list_head lists[NR_BPF_LRU_LIST_T];
	unsigned int counts[NR_BPF_LRU_LIST_COUNT];
	/* The next inactive list rotation starts from here */
	struct bb_list_head __bpfbox *next_inactive_rotation;

	raw_spinlock_t lock ____cacheline_aligned_in_smp;
};

struct bb_bpf_lru_locallist {
	struct bb_list_head lists[NR_BPF_LRU_LOCAL_LIST_T];
	u16 next_steal;
	raw_spinlock_t lock;
};

struct bb_bpf_common_lru {
	struct bb_bpf_lru_list lru_list;
	struct bb_bpf_lru_locallist __bpfbox *local_list;
};

typedef bool (*bb_del_from_htab_func)(void *arg, struct bb_bpf_lru_node __bpfbox *node);

struct bb_bpf_lru {
	struct bb_bpf_common_lru common_lru;
	bb_del_from_htab_func del_from_htab;
	void *del_arg;
	unsigned int hash_offset;
	unsigned int nr_scans;
	bool percpu;
};

#endif
