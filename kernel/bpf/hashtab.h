#ifndef _HASHTAB_H
#define _HASHTAB_H 1

#include <linux/bpf.h>
#include <linux/bpfbox.h>
#include <linux/jhash.h>
#include <asm/local.h>
/* #include <linux/rculist_nulls.h> */
#include <linux/rcupdate.h>
#include <linux/bpf_mem_alloc.h>
#include "percpu_freelist.h"
#include "bpf_lru_list.h"

#include <linux/poison.h>
#include <linux/const.h>

#define unbox bpf_unbox_ptr
#define box bpf_box_ptr

struct bb_hlist_nulls_head {
	struct bb_hlist_nulls_node __bpfbox *first;
};

struct bb_hlist_nulls_node {
	struct bb_hlist_nulls_node __bpfbox *next;
	struct bb_hlist_nulls_node __bpfbox * __bpfbox *pprev;
};

#define __BB_WRITE_ONCE(x, val)						\
do {									\
	*(unbox((volatile typeof(x) *)&(x))) = (val);			\
} while (0)

#define BB_WRITE_ONCE(x, val)						\
do {									\
	compiletime_assert_rwonce_type(x);				\
	__BB_WRITE_ONCE((x), (val));					\
} while (0)

#define BB_READ_ONCE(x)						\
({								\
	(*unbox((const volatile typeof(x) *)&(x)));		\
})

#define bb_rcu_assign_pointer(p, v)	\
do {					\
	barrier();			\
	BB_WRITE_ONCE((p), (v));	\
} while (0)

#define BB_NULLS_MARKER(value) (1UL | (((long)value) << 1))

/* ptr here is ordinary pointer */
#define BB_INIT_HLIST_NULLS_HEAD(ptr, nulls) \
	(*unbox(&(ptr)->first) = (struct bb_hlist_nulls_node __bpfbox *) NULLS_MARKER(nulls))

static inline int bb_is_a_nulls(const struct bb_hlist_nulls_node __bpfbox *ptr)
{
	return ((unsigned long)ptr & 1);
}

static inline unsigned long bb_get_nulls_value(const struct bb_hlist_nulls_node __bpfbox *ptr)
{
	return ((unsigned long)ptr) >> 1;
}

#define bb_hlist_nulls_entry(ptr, type, member) box_container_of(ptr,type,member)

#define bb_hlist_nulls_entry_safe(ptr, type, member)	\
	({ typeof(ptr) ____ptr = (ptr); \
	   !bb_is_a_nulls(____ptr) ? bb_hlist_nulls_entry(____ptr, type, member) : NULL; \
	})

#define bb_hlist_nulls_entry(ptr, type, member) box_container_of(ptr,type,member)

#define bb_hlist_nulls_first_rcu(head)					\
	((struct bb_hlist_nulls_node __bpfbox*)*unbox(((struct bb_hlist_nulls_node __rcu __force **)&(head)->first)))

#define bb_hlist_nulls_next_rcu(node) \
	((struct bb_hlist_nulls_node __bpfbox*)(*unbox(((struct bb_hlist_nulls_node __rcu __force **)&(node)->next))))

#define bb_hlist_nulls_for_each_entry_rcu(tpos, pos, head, member)		\
	for (({barrier();}),							\
	     pos = BB_READ_ONCE((head)->first);					\
		(!bb_is_a_nulls(pos)) &&					\
		({ tpos = bb_hlist_nulls_entry(pos, typeof(*tpos), member); 1; }); \
		pos = BB_READ_ONCE(pos->next))

#define bb_hlist_nulls_for_each_entry_safe(tpos, pos, head, member)		\
	for (({barrier();}),							\
	     pos = BB_READ_ONCE((head)->first);					\
		(!bb_is_a_nulls(pos)) &&					\
		({ tpos = bb_hlist_nulls_entry(pos, typeof(*tpos), member);	\
		pos = BB_READ_ONCE(pos->next); 1; });)

#define bb_hlist_nulls_for_each_entry(tpos, pos, head, member)			\
	for (pos = *unbox(&(head)->first);				\
	(!bb_is_a_nulls(pos)) &&					\
		({ tpos = bb_hlist_nulls_entry(pos, typeof(*tpos), member); 1;}); \
	     pos = *unbox(&pos->next))
/*
 * The bucket lock has two protection scopes:
 *
 * 1) Serializing concurrent operations from BPF programs on different
 *    CPUs
 *
 * 2) Serializing concurrent operations from BPF programs and sys_bpf()
 *
 * BPF programs can execute in any context including perf, kprobes and
 * tracing. As there are almost no limits where perf, kprobes and tracing
 * can be invoked from the lock operations need to be protected against
 * deadlocks. Deadlocks can be caused by recursion and by an invocation in
 * the lock held section when functions which acquire this lock are invoked
 * from sys_bpf(). BPF recursion is prevented by incrementing the per CPU
 * variable bpf_prog_active, which prevents BPF programs attached to perf
 * events, kprobes and tracing to be invoked before the prior invocation
 * from one of these contexts completed. sys_bpf() uses the same mechanism
 * by pinning the task to the current CPU and incrementing the recursion
 * protection across the map operation.
 *
 * This has subtle implications on PREEMPT_RT. PREEMPT_RT forbids certain
 * operations like memory allocations (even with GFP_ATOMIC) from atomic
 * contexts. This is required because even with GFP_ATOMIC the memory
 * allocator calls into code paths which acquire locks with long held lock
 * sections. To ensure the deterministic behaviour these locks are regular
 * spinlocks, which are converted to 'sleepable' spinlocks on RT. The only
 * true atomic contexts on an RT kernel are the low level hardware
 * handling, scheduling, low level interrupt handling, NMIs etc. None of
 * these contexts should ever do memory allocations.
 *
 * As regular device interrupt handlers and soft interrupts are forced into
 * thread context, the existing code which does
 *   spin_lock*(); alloc(GFP_ATOMIC); spin_unlock*();
 * just works.
 *
 * In theory the BPF locks could be converted to regular spinlocks as well,
 * but the bucket locks and percpu_freelist locks can be taken from
 * arbitrary contexts (perf, kprobes, tracepoints) which are required to be
 * atomic contexts even on RT. Before the introduction of bpf_mem_alloc,
 * it is only safe to use raw spinlock for preallocated hash map on a RT kernel,
 * because there is no memory allocation within the lock held sections. However
 * after hash map was fully converted to use bpf_mem_alloc, there will be
 * non-synchronous memory allocation for non-preallocated hash map, so it is
 * safe to always use raw spinlock for bucket lock.
 */
struct bucket {
	struct bb_hlist_nulls_head head;
	raw_spinlock_t raw_lock;
};

#define HASHTAB_MAP_LOCK_COUNT 8
#define HASHTAB_MAP_LOCK_MASK (HASHTAB_MAP_LOCK_COUNT - 1)

struct bpf_htab_inner {
	struct bpf_map_inner map_inner;
	struct bpf_htab *htab;
	struct bucket __bpfbox *buckets;
	struct htab_elem __bpfbox *__bpfbox *extra_elems;
	u32 hashrnd;
	u32 n_buckets;
	local_t __bpfbox * __bpfbox *map_locked;
};

struct bpf_htab {
	struct bpf_map map;
	struct bpf_mem_alloc ma;
	struct bpf_mem_alloc pcpu_ma;
	struct bucket *buckets;
	struct htab_elem *__bpfbox *extra_elems;
	void *elems;
	union {
		struct pcpu_freelist freelist;
		struct bpf_lru lru;
	};
	/* number of elements in non-preallocated hashtable are kept
	 * in either pcount or count
	 */
	struct percpu_counter pcount;
	atomic_t count;
	bool use_percpu_counter;
	u32 n_buckets;	/* number of hash buckets */
	u32 elem_size;	/* size of each element in bytes */
	u32 hashrnd;
	struct lock_class_key lockdep_key;
};
#define htab_inner(htab) (container_of((htab)->map.map_inner, struct bpf_htab_inner, map_inner))

/* each htab element is struct htab_elem + key + value */
struct htab_elem {
	union {
		struct bb_hlist_nulls_node hash_node;
		struct {
			void *padding;
			union {
				struct pcpu_freelist_node fnode;
				struct htab_elem *batch_flink;
			};
		};
	};
	union {
		/* pointer to per-cpu pointer */
		void *ptr_to_pptr;
		struct bpf_lru_node lru_node;
	};
	u32 hash;
	char key[] __aligned(8);
};

#endif /* _HASHTAB_H */
