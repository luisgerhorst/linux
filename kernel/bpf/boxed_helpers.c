#include <linux/kernel.h>
#include <linux/bpf.h>
#include <linux/bpfbox.h>
#include "hashtab.h"


register unsigned long base asm ("r12");
#undef unbox
#undef box

#define unbox(p)	\
({			\
	BPFBOX_CHECK_VALID((p));	\
	(typeof(*(p)) __kernel __force *)(base + ((unsigned long)(p) & 0xffffffff)); \
})

#define box(p)	\
({		\
	void __bpfbox *ptr;			\
	ptr = (void __bpfbox*)((unsigned long)(p) - base);	\
	BPFBOX_CHECK_VALID(ptr);		\
	(typeof(*(p)) __bpfbox *) ptr;		\
})

void __bpfbox *open_bpf_scratch(int size)
{
	struct bpfbox_scratch_region *region;
	long cur;
	region = raw_cpu_ptr(&bpfbox_scratch_region);
	cur = local_add_return(size, &region->sp);
	return (void __bpfbox *)cur;
}

void close_bpf_scratch(int size)
{
	struct bpfbox_scratch_region *region = this_cpu_ptr(&bpfbox_scratch_region);
	local_sub(size, &region->sp);
}

static inline void __bb_list_add(struct bb_list_head __bpfbox *new,
			         struct bb_list_head __bpfbox *prev,
			         struct bb_list_head __bpfbox *next)
{
	*unbox(&next->prev) = new;
	*unbox(&new->next) = next;
	*unbox(&new->prev) = prev;
	BB_WRITE_ONCE(prev->next, new);
}

static inline void bb_list_add(struct bb_list_head __bpfbox *new,
			struct bb_list_head __bpfbox *head)
{
	__bb_list_add(new, head, *unbox(&head->next));
}

static inline void __bb_list_del(struct bb_list_head __bpfbox *prev,
			      struct bb_list_head __bpfbox *next)
{
	*unbox(&next->prev) = prev;
	BB_WRITE_ONCE(prev->next, next);
}

static inline void __bb_list_del_entry(struct bb_list_head __bpfbox *entry)
{
	__bb_list_del(*unbox(&entry->prev), *unbox(&entry->next));
}

static inline void bb_list_del(struct bb_list_head __bpfbox *entry)
{
	__bb_list_del_entry(entry);
	*unbox(&entry->next) = (void __force __bpfbox *)LIST_POISON1;
	*unbox(&entry->prev) = (void __force __bpfbox *)LIST_POISON2;
}

static inline void bb_list_move(struct bb_list_head __bpfbox *list,
				struct bb_list_head __bpfbox *head)
{
	__bb_list_del(*unbox(&list->prev), *unbox(&list->next));
	bb_list_add(list, head);
}

static inline int bb_list_empty(const struct bb_list_head __bpfbox *head)
{
	return BB_READ_ONCE(head->next) == head;
}

static inline void BB_INIT_LIST_HEAD(struct bb_list_head __bpfbox *list)
{
	BB_WRITE_ONCE(list->next, list);
	BB_WRITE_ONCE(list->prev, list);
}

#define LOCAL_FREE_TARGET		(128)
#define LOCAL_NR_SCANS			LOCAL_FREE_TARGET

#define PERCPU_FREE_TARGET		(4)
#define PERCPU_NR_SCANS			PERCPU_FREE_TARGET

/* Helpers to get the local list index */
#define LOCAL_LIST_IDX(t)	((t) - BPF_LOCAL_LIST_T_OFFSET)
#define LOCAL_FREE_LIST_IDX	LOCAL_LIST_IDX(BPF_LRU_LOCAL_LIST_T_FREE)
#define LOCAL_PENDING_LIST_IDX	LOCAL_LIST_IDX(BPF_LRU_LOCAL_LIST_T_PENDING)
#define IS_LOCAL_LIST_TYPE(t)	((t) >= BPF_LOCAL_LIST_T_OFFSET)

static int get_next_cpu(int cpu)
{
	cpu = cpumask_next(cpu, cpu_possible_mask);
	if (cpu >= nr_cpu_ids)
		cpu = cpumask_first(cpu_possible_mask);
	return cpu;
}

/* Local list helpers */
static struct bb_list_head __bpfbox *local_free_list(struct bb_bpf_lru_locallist __bpfbox *loc_l)
{
	return &loc_l->lists[LOCAL_FREE_LIST_IDX];
}

static struct bb_list_head __bpfbox *local_pending_list(struct bb_bpf_lru_locallist __bpfbox *loc_l)
{
	return &loc_l->lists[LOCAL_PENDING_LIST_IDX];
}

/* bpf_lru_node helpers */
static bool bpf_lru_node_is_ref(const struct bb_bpf_lru_node __bpfbox *node)
{
	return *unbox(&node->ref);
}

static void bpf_lru_list_count_inc(struct bb_bpf_lru_list __bpfbox *l,
				   enum bpf_lru_list_type type)
{
	if (type < NR_BPF_LRU_LIST_COUNT)
		(*unbox(&l->counts[type]))++;
}

static void bpf_lru_list_count_dec(struct bb_bpf_lru_list __bpfbox *l,
				   enum bpf_lru_list_type type)
{
	if (type < NR_BPF_LRU_LIST_COUNT)
		(*unbox(&l->counts[type]))--;
}

static void __bpf_lru_node_move_to_free(struct bb_bpf_lru_list __bpfbox *l,
					struct bb_bpf_lru_node __bpfbox *node,
					struct bb_list_head __bpfbox *free_list,
					enum bpf_lru_list_type tgt_free_type)
{
	if (WARN_ON_ONCE(IS_LOCAL_LIST_TYPE(*unbox(&node->type))))
		return;

	/* If the removing node is the next_inactive_rotation candidate,
	 * move the next_inactive_rotation pointer also.
	 */
	if (&node->list == *unbox(&l->next_inactive_rotation))
		*unbox(&l->next_inactive_rotation) = (unbox(*unbox(&l->next_inactive_rotation)))->prev;

	bpf_lru_list_count_dec(l, *unbox(&node->type));

	*unbox(&node->type) = tgt_free_type;
	bb_list_move(&node->list, free_list);
}

/* Move nodes from local list to the LRU list */
static void __bpf_lru_node_move_in(struct bb_bpf_lru_list __bpfbox *l,
				   struct bb_bpf_lru_node __bpfbox *node,
				   enum bpf_lru_list_type tgt_type)
{
	if (WARN_ON_ONCE(!IS_LOCAL_LIST_TYPE(*unbox(&node->type))) ||
	    WARN_ON_ONCE(IS_LOCAL_LIST_TYPE(tgt_type)))
		return;

	bpf_lru_list_count_inc(l, tgt_type);
	*unbox(&node->type) = tgt_type;
	*unbox(&node->ref) = 0;
	bb_list_move(&node->list, &l->lists[tgt_type]);
}

/* Move nodes between or within active and inactive list (like
 * active to inactive, inactive to active or tail of active back to
 * the head of active).
 */
static void __bpf_lru_node_move(struct bb_bpf_lru_list __bpfbox *l,
				struct bb_bpf_lru_node __bpfbox *node,
				enum bpf_lru_list_type tgt_type)
{
	if (WARN_ON_ONCE(IS_LOCAL_LIST_TYPE(*unbox(&node->type))) ||
	    WARN_ON_ONCE(IS_LOCAL_LIST_TYPE(tgt_type)))
		return;

	if (*unbox(&node->type) != tgt_type) {
		bpf_lru_list_count_dec(l, *unbox(&node->type));
		bpf_lru_list_count_inc(l, tgt_type);
		*unbox(&node->type) = tgt_type;
	}
	*unbox(&node->ref) = 0;

	/* If the moving node is the next_inactive_rotation candidate,
	 * move the next_inactive_rotation pointer also.
	 */
	if (&node->list == *unbox(&l->next_inactive_rotation))
		*unbox(&l->next_inactive_rotation) = (unbox(*unbox(&l->next_inactive_rotation)))->prev;

	bb_list_move(&node->list, &l->lists[tgt_type]);
}

static bool bpf_lru_list_inactive_low(const struct bb_bpf_lru_list __bpfbox *l)
{
	return *unbox(&l->counts[BPF_LRU_LIST_T_INACTIVE]) <
		*unbox(&l->counts[BPF_LRU_LIST_T_ACTIVE]);
}

/* Rotate the active list:
 * 1. Start from tail
 * 2. If the node has the ref bit set, it will be rotated
 *    back to the head of active list with the ref bit cleared.
 *    Give this node one more chance to survive in the active list.
 * 3. If the ref bit is not set, move it to the head of the
 *    inactive list.
 * 4. It will at most scan nr_scans nodes
 */
static void __bpf_lru_list_rotate_active(struct bb_bpf_lru __bpfbox *lru,
					 struct bb_bpf_lru_list __bpfbox *l)
{
	struct bb_list_head __bpfbox *active = &l->lists[BPF_LRU_LIST_T_ACTIVE];
	struct bb_bpf_lru_node __bpfbox *node, *tmp_node, *first_node;
	unsigned int i = 0;

	first_node = list_first_entry(active, struct bb_bpf_lru_node, list);
	list_for_each_entry_safe_reverse(node, tmp_node, active, list) {
		if (bpf_lru_node_is_ref(node))
			__bpf_lru_node_move(l, node, BPF_LRU_LIST_T_ACTIVE);
		else
			__bpf_lru_node_move(l, node, BPF_LRU_LIST_T_INACTIVE);

		if (++i == *unbox(&lru->nr_scans) || node == first_node)
			break;
	}
}

/* Rotate the inactive list.  It starts from the next_inactive_rotation
 * 1. If the node has ref bit set, it will be moved to the head
 *    of active list with the ref bit cleared.
 * 2. If the node does not have ref bit set, it will leave it
 *    at its current location (i.e. do nothing) so that it can
 *    be considered during the next inactive_shrink.
 * 3. It will at most scan nr_scans nodes
 */
static void __bpf_lru_list_rotate_inactive(struct bb_bpf_lru __bpfbox *lru,
					   struct bb_bpf_lru_list __bpfbox *l)
{
	struct bb_list_head __bpfbox *inactive = &l->lists[BPF_LRU_LIST_T_INACTIVE];
	struct bb_list_head __bpfbox *cur, *last, *next = inactive;
	struct bb_bpf_lru_node __bpfbox *node;
	unsigned int i = 0;

	if (bb_list_empty(inactive))
		return;

	last = (unbox(*unbox(&l->next_inactive_rotation)))->next;
	if (last == inactive)
		last = *unbox(&last->next);

	cur = *unbox(&l->next_inactive_rotation);
	while (i < *unbox(&lru->nr_scans)) {
		if (cur == inactive) {
			cur = *unbox(&cur->prev);
			continue;
		}

		node = list_entry(cur, struct bb_bpf_lru_node, list);
		next = *unbox(&cur->prev);
		if (bpf_lru_node_is_ref(node))
			__bpf_lru_node_move(l, node, BPF_LRU_LIST_T_ACTIVE);
		if (cur == last)
			break;
		cur = next;
		i++;
	}

	*unbox(&l->next_inactive_rotation) = next;
}

/* Shrink the inactive list.  It starts from the tail of the
 * inactive list and only move the nodes without the ref bit
 * set to the designated free list.
 */
static unsigned int
__bpf_lru_list_shrink_inactive(struct bb_bpf_lru __bpfbox *lru,
			       struct bb_bpf_lru_list __bpfbox *l,
			       unsigned int tgt_nshrink,
			       struct bb_list_head __bpfbox *free_list,
			       enum bpf_lru_list_type tgt_free_type)
{
	struct bb_list_head __bpfbox *inactive = &l->lists[BPF_LRU_LIST_T_INACTIVE];
	struct bb_bpf_lru_node __bpfbox *node, *tmp_node;
	unsigned int nshrinked = 0;
	unsigned int i = 0;

	list_for_each_entry_safe_reverse(node, tmp_node, inactive, list) {
		if (bpf_lru_node_is_ref(node)) {
			__bpf_lru_node_move(l, node, BPF_LRU_LIST_T_ACTIVE);
		} else if ((*unbox(&lru->del_from_htab))(*unbox(&lru->del_arg), node)) {
			__bpf_lru_node_move_to_free(l, node, free_list,
						    tgt_free_type);
			if (++nshrinked == tgt_nshrink)
				break;
		}

		if (++i == *unbox(&lru->nr_scans))
			break;
	}

	return nshrinked;
}

/* 1. Rotate the active list (if needed)
 * 2. Always rotate the inactive list
 */
static void __bpf_lru_list_rotate(struct bb_bpf_lru __bpfbox *lru, struct bb_bpf_lru_list __bpfbox *l)
{
	if (bpf_lru_list_inactive_low(l))
		__bpf_lru_list_rotate_active(lru, l);

	__bpf_lru_list_rotate_inactive(lru, l);
}

/* Calls __bpf_lru_list_shrink_inactive() to shrink some
 * ref-bit-cleared nodes and move them to the designated
 * free list.
 *
 * If it cannot get a free node after calling
 * __bpf_lru_list_shrink_inactive().  It will just remove
 * one node from either inactive or active list without
 * honoring the ref-bit.  It prefers inactive list to active
 * list in this situation.
 */
static unsigned int __bpf_lru_list_shrink(struct bb_bpf_lru __bpfbox *lru,
					  struct bb_bpf_lru_list __bpfbox *l,
					  unsigned int tgt_nshrink,
					  struct bb_list_head __bpfbox *free_list,
					  enum bpf_lru_list_type tgt_free_type)

{
	struct bb_bpf_lru_node __bpfbox *node, *tmp_node;
	struct bb_list_head __bpfbox *force_shrink_list;
	unsigned int nshrinked;

	nshrinked = __bpf_lru_list_shrink_inactive(lru, l, tgt_nshrink,
						   free_list, tgt_free_type);
	if (nshrinked)
		return nshrinked;

	/* Do a force shrink by ignoring the reference bit */
	if (!bb_list_empty(&l->lists[BPF_LRU_LIST_T_INACTIVE]))
		force_shrink_list = &l->lists[BPF_LRU_LIST_T_INACTIVE];
	else
		force_shrink_list = &l->lists[BPF_LRU_LIST_T_ACTIVE];

	list_for_each_entry_safe_reverse(node, tmp_node, force_shrink_list,
					 list) {
		if ((*unbox(&lru->del_from_htab))(*unbox(&lru->del_arg), node)) {
			__bpf_lru_node_move_to_free(l, node, free_list,
						    tgt_free_type);
			return 1;
		}
	}

	return 0;
}

/* Flush the nodes from the local pending list to the LRU list */
static void __local_list_flush(struct bb_bpf_lru_list __bpfbox *l,
			       struct bb_bpf_lru_locallist __bpfbox *loc_l)
{
	struct bb_bpf_lru_node __bpfbox *node, *tmp_node;

	list_for_each_entry_safe_reverse(node, tmp_node,
					 local_pending_list(loc_l), list) {
		if (bpf_lru_node_is_ref(node))
			__bpf_lru_node_move_in(l, node, BPF_LRU_LIST_T_ACTIVE);
		else
			__bpf_lru_node_move_in(l, node,
					       BPF_LRU_LIST_T_INACTIVE);
	}
}

static void bpf_lru_list_push_free(struct bb_bpf_lru_list __bpfbox *l,
				   struct bb_bpf_lru_node __bpfbox *node)
{
	unsigned long flags;

	if (WARN_ON_ONCE(IS_LOCAL_LIST_TYPE(*unbox(&node->type))))
		return;

	raw_spin_lock_irqsave(unbox(&l->lock), flags);
	__bpf_lru_node_move(l, node, BPF_LRU_LIST_T_FREE);
	raw_spin_unlock_irqrestore(unbox(&l->lock), flags);
}

static void bpf_lru_list_pop_free_to_local(struct bb_bpf_lru __bpfbox *lru,
					   struct bb_bpf_lru_locallist __bpfbox *loc_l)
{
	struct bb_bpf_lru_list __bpfbox *l = &lru->common_lru.lru_list;
	struct bb_bpf_lru_node __bpfbox *node, *tmp_node;
	unsigned int nfree = 0;

	raw_spin_lock(unbox(&l->lock));

	__local_list_flush(l, loc_l);

	__bpf_lru_list_rotate(lru, l);

	list_for_each_entry_safe(node, tmp_node, &l->lists[BPF_LRU_LIST_T_FREE],
				 list) {
		__bpf_lru_node_move_to_free(l, node, local_free_list(loc_l),
					    BPF_LRU_LOCAL_LIST_T_FREE);
		if (++nfree == LOCAL_FREE_TARGET)
			break;
	}

	if (nfree < LOCAL_FREE_TARGET)
		__bpf_lru_list_shrink(lru, l, LOCAL_FREE_TARGET - nfree,
				      local_free_list(loc_l),
				      BPF_LRU_LOCAL_LIST_T_FREE);

	raw_spin_unlock(unbox(&l->lock));
}

static void __local_list_add_pending(struct bb_bpf_lru __bpfbox *lru,
				     struct bb_bpf_lru_locallist  __bpfbox *loc_l,
				     int cpu,
				     struct bb_bpf_lru_node __bpfbox *node,
				     u32 hash)
{
	*unbox((u32 __bpfbox *)((void __bpfbox*)node + *unbox(&lru->hash_offset))) = hash;
	*unbox(&node->cpu) = cpu;
	*unbox(&node->type) = BPF_LRU_LOCAL_LIST_T_PENDING;
	*unbox(&node->ref) = 0;
	bb_list_add(&node->list, local_pending_list(loc_l));
}

static struct bb_bpf_lru_node __bpfbox*
__local_list_pop_free(struct bb_bpf_lru_locallist __bpfbox *loc_l)
{
	struct bb_bpf_lru_node __bpfbox *node;

	node = list_first_entry_or_null(local_free_list(loc_l),
					struct bb_bpf_lru_node,
					list);
	if (node)
		bb_list_del(&node->list);

	return node;
}

static struct bb_bpf_lru_node __bpfbox *
__local_list_pop_pending(struct bb_bpf_lru __bpfbox *lru, struct bb_bpf_lru_locallist __bpfbox *loc_l)
{
	struct bb_bpf_lru_node __bpfbox *node;
	bool force = false;

ignore_ref:
	/* Get from the tail (i.e. older element) of the pending list. */
	list_for_each_entry_reverse(node, local_pending_list(loc_l),
				    list) {
		if ((!bpf_lru_node_is_ref(node) || force) &&
			(*unbox(&lru->del_from_htab))(*unbox(&lru->del_arg), node)) {
			bb_list_del(&node->list);
			return node;
		}
	}

	if (!force) {
		force = true;
		goto ignore_ref;
	}

	return NULL;
}

static struct bb_bpf_lru_node __bpfbox *bpf_common_lru_pop_free(struct bb_bpf_lru __bpfbox *lru,
						    		u32 hash)
{
	struct bb_bpf_lru_locallist __bpfbox *loc_l, *steal_loc_l;
	struct bb_bpf_common_lru __bpfbox *clru = &lru->common_lru;
	struct bb_bpf_lru_node __bpfbox *node;
	int steal, first_steal;
	unsigned long flags;
	int cpu = raw_smp_processor_id();

	loc_l = &(*unbox(&clru->local_list))[cpu];

	raw_spin_lock_irqsave(unbox(&loc_l->lock), flags);

	node = __local_list_pop_free(loc_l);
	if (!node) {
		bpf_lru_list_pop_free_to_local(lru, loc_l);
		node = __local_list_pop_free(loc_l);
	}

	if (node)
		__local_list_add_pending(lru, loc_l, cpu, node, hash);

	raw_spin_unlock_irqrestore(unbox(&loc_l->lock), flags);

	if (node)
		return node;

	/* No free nodes found from the local free list and
	 * the global LRU list.
	 *
	 * Steal from the local free/pending list of the
	 * current CPU and remote CPU in RR.  It starts
	 * with the loc_l->next_steal CPU.
	 */

	first_steal = *unbox(&loc_l->next_steal);
	steal = first_steal;
	do {
		steal_loc_l = &(*unbox(&clru->local_list))[steal];

		raw_spin_lock_irqsave(unbox(&steal_loc_l->lock), flags);

		node = __local_list_pop_free(steal_loc_l);
		if (!node)
			node = __local_list_pop_pending(lru, steal_loc_l);

		raw_spin_unlock_irqrestore(unbox(&steal_loc_l->lock), flags);

		steal = get_next_cpu(steal);
	} while (!node && steal != first_steal);

	*unbox(&loc_l->next_steal) = steal;

	if (node) {
		raw_spin_lock_irqsave(unbox(&loc_l->lock), flags);
		__local_list_add_pending(lru, loc_l, cpu, node, hash);
		raw_spin_unlock_irqrestore(unbox(&loc_l->lock), flags);
	}

	return node;
}

static struct bb_bpf_lru_node __bpfbox *bb_bpf_lru_pop_free(struct bb_bpf_lru __bpfbox *lru, u32 hash)
{
	if (*unbox(&lru->percpu))
		BUG();
	else
		return bpf_common_lru_pop_free(lru, hash);
}

static void bpf_common_lru_push_free(struct bb_bpf_lru __bpfbox *lru,
				     struct bb_bpf_lru_node __bpfbox *node)
{
	u8 node_type = BB_READ_ONCE(node->type);
	unsigned long flags;

	if (WARN_ON_ONCE(node_type == BPF_LRU_LIST_T_FREE) ||
	    WARN_ON_ONCE(node_type == BPF_LRU_LOCAL_LIST_T_FREE))
		return;

	if (node_type == BPF_LRU_LOCAL_LIST_T_PENDING) {
		struct bb_bpf_lru_locallist __bpfbox *loc_l;

		loc_l = &(*unbox(&lru->common_lru.local_list))[*unbox(&node->cpu)];

		raw_spin_lock_irqsave(unbox(&loc_l->lock), flags);

		if (unlikely(*unbox(&node->type) != BPF_LRU_LOCAL_LIST_T_PENDING)) {
			raw_spin_unlock_irqrestore(unbox(&loc_l->lock), flags);
			goto check_lru_list;
		}

		*unbox(&node->type) = BPF_LRU_LOCAL_LIST_T_FREE;
		*unbox(&node->ref) = 0;
		bb_list_move(&node->list, local_free_list(loc_l));

		raw_spin_unlock_irqrestore(unbox(&loc_l->lock), flags);
		return;
	}

check_lru_list:
	bpf_lru_list_push_free(&lru->common_lru.lru_list, node);
}

static void bb_bpf_lru_push_free(struct bb_bpf_lru __bpfbox *lru, struct bb_bpf_lru_node __bpfbox *node)
{
	if (*unbox(&lru->percpu))
		BUG();
	else
		bpf_common_lru_push_free(lru, node);
}

static inline void bb_hlist_nulls_add_head_rcu(struct bb_hlist_nulls_node __bpfbox *n,
					struct bb_hlist_nulls_head __bpfbox *h)
{
	struct bb_hlist_nulls_node __bpfbox *first = *unbox(&h->first);

	*unbox(&n->next) = first;
	BB_WRITE_ONCE(n->pprev, &h->first);
	bb_rcu_assign_pointer(h->first, n);
	if (!bb_is_a_nulls(first))
		BB_WRITE_ONCE(first->pprev, &n->next);
}

static inline void __bb_hlist_nulls_del(struct bb_hlist_nulls_node __bpfbox *n)
{
	struct bb_hlist_nulls_node __bpfbox *next = *unbox(&n->next);
	struct bb_hlist_nulls_node __bpfbox * __bpfbox *pprev = *unbox(&n->pprev);

	BB_WRITE_ONCE(*pprev, next);
	if (!bb_is_a_nulls(next))
		BB_WRITE_ONCE(next->pprev, pprev);
}

static inline void bb_hlist_nulls_del_rcu(struct bb_hlist_nulls_node __bpfbox *n)
{
	__bb_hlist_nulls_del(n);
	BB_WRITE_ONCE(n->pprev, (void __force __bpfbox *)LIST_POISON2);
}


static struct bb_pcpu_freelist_node __bpfbox *___bb_pcpu_freelist_pop(struct bb_pcpu_freelist __bpfbox *s)
{
	struct bb_pcpu_freelist_head __bpfbox *head;
	struct bb_pcpu_freelist_node __bpfbox *node;
	int cpu;

	for_each_cpu_wrap(cpu, cpu_possible_mask, raw_smp_processor_id()) {
		head = unbox(*unbox(&s->freelist))[cpu];
		if (!BB_READ_ONCE(head->first))
			continue;
		raw_spin_lock(unbox(&head->lock));
		node = *unbox(&head->first);
		if (node) {
			BB_WRITE_ONCE(head->first, *unbox(&node->next));
			raw_spin_unlock(unbox(&head->lock));
			return node;
		}
		raw_spin_unlock(unbox(&head->lock));
	}

	/* per cpu lists are all empty, try extralist */
	if (!BB_READ_ONCE(s->extralist.first))
		return NULL;
	BUG();
	return NULL;
}

static struct bb_pcpu_freelist_node __bpfbox *__bb_pcpu_freelist_pop(struct bb_pcpu_freelist __bpfbox *s)
{
	if (in_nmi())
		BUG();
		/* return ___pcpu_freelist_pop_nmi(s); */
	return ___bb_pcpu_freelist_pop(s);
}

void __bpfbox *__percpu_array_map_lookup_elem(struct bpf_map_inner __bpfbox *inner,
					    void __bpfbox *key)
{
	u32 index = *(u32 *)(unbox(key));
	int i = raw_smp_processor_id();
	struct bpf_array_inner __bpfbox *array =
		box_container_of(inner, struct bpf_array_inner, map_inner);
	void __bpfbox *pptr = *unbox(&array->pptrs[i]);
	if (unlikely(index >= unbox(inner)->max_entries))
		return NULL;
	return pptr + index * unbox(array)->elem_size;
}


/* __jhash_mix -- mix 3 32-bit values reversibly. */
#define __jhash_mix(a, b, c)			\
{						\
	a -= c;  a ^= rol32(c, 4);  c += b;	\
	b -= a;  b ^= rol32(a, 6);  a += c;	\
	c -= b;  c ^= rol32(b, 8);  b += a;	\
	a -= c;  a ^= rol32(c, 16); c += b;	\
	b -= a;  b ^= rol32(a, 19); a += c;	\
	c -= b;  c ^= rol32(b, 4);  b += a;	\
}

/* __jhash_final - final mixing of 3 32-bit values (a,b,c) into c */
#define __jhash_final(a, b, c)			\
{						\
	c ^= b; c -= rol32(b, 14);		\
	a ^= c; a -= rol32(c, 11);		\
	b ^= a; b -= rol32(a, 25);		\
	c ^= b; c -= rol32(b, 16);		\
	a ^= c; a -= rol32(c, 4);		\
	b ^= a; b -= rol32(a, 14);		\
	c ^= b; c -= rol32(b, 24);		\
}

static inline u32 bpfbox_jhash(const void __bpfbox *key, u32 length, u32 initval)
{
	/* u32 a, b, c; */
	/* const u8 __bpfbox *k = key; */

	/* /\* Set up the internal state *\/ */
	/* a = b = c = JHASH_INITVAL + length + initval; */

	/* /\* All but the last block: affect some 32 bits of (a,b,c) *\/ */
	/* while (length > 12) { */
	/* 	a += __get_unaligned_cpu32(unbox(k)); */
	/* 	b += __get_unaligned_cpu32(unbox(k + 4)); */
	/* 	c += __get_unaligned_cpu32(unbox(k + 8)); */
	/* 	__jhash_mix(a, b, c); */
	/* 	length -= 12; */
	/* 	k += 12; */
	/* } */
	/* /\* Last block: affect all 32 bits of (c) *\/ */
	/* switch (length) { */
	/* case 12: c += (u32)*unbox(&k[11])<<24;	fallthrough; */
	/* case 11: c += (u32)*unbox(&k[10])<<16;	fallthrough; */
	/* case 10: c += (u32)*unbox(&k[9])<<8;	fallthrough; */
	/* case 9:  c += *unbox(&k[8]);		fallthrough; */
	/* case 8:  b += (u32)*unbox(&k[7])<<24;	fallthrough; */
	/* case 7:  b += (u32)*unbox(&k[6])<<16;	fallthrough; */
	/* case 6:  b += (u32)*unbox(&k[5])<<8;	fallthrough; */
	/* case 5:  b += *unbox(&k[4]);		fallthrough; */
	/* case 4:  a += (u32)*unbox(&k[3])<<24;	fallthrough; */
	/* case 3:  a += (u32)*unbox(&k[2])<<16;	fallthrough; */
	/* case 2:  a += (u32)*unbox(&k[1])<<8;	fallthrough; */
	/* case 1:  a += *unbox(&k[0]); */
	/* 	 __jhash_final(a, b, c); */
	/* 	 break; */
	/* case 0: /\* Nothing left to add *\/ */
	/* 	break; */
	/* } */

	/* return c; */
	u32 a, b, c;
	const u8 *k = unbox(key);

	/* Set up the internal state */
	a = b = c = JHASH_INITVAL + length + initval;

	/* All but the last block: affect some 32 bits of (a,b,c) */
	while (length > 12) {
		a += __get_unaligned_cpu32(k);
		b += __get_unaligned_cpu32(k + 4);
		c += __get_unaligned_cpu32(k + 8);
		__jhash_mix(a, b, c);
		length -= 12;
		k += 12;
	}
	/* Last block: affect all 32 bits of (c) */
	switch (length) {
	case 12: c += (u32)k[11]<<24;	fallthrough;
	case 11: c += (u32)k[10]<<16;	fallthrough;
	case 10: c += (u32)k[9]<<8;	fallthrough;
	case 9:  c += k[8];		fallthrough;
	case 8:  b += (u32)k[7]<<24;	fallthrough;
	case 7:  b += (u32)k[6]<<16;	fallthrough;
	case 6:  b += (u32)k[5]<<8;	fallthrough;
	case 5:  b += k[4];		fallthrough;
	case 4:  a += (u32)k[3]<<24;	fallthrough;
	case 3:  a += (u32)k[2]<<16;	fallthrough;
	case 2:  a += (u32)k[1]<<8;	fallthrough;
	case 1:  a += k[0];
		 __jhash_final(a, b, c);
		 break;
	case 0: /* Nothing left to add */
		break;
	}

	return c;
}

static inline u32 htab_map_hash(const void __bpfbox *key, u32 key_len, u32 hashrnd)
{
	return bpfbox_jhash(key, key_len, hashrnd);
}

static inline struct bucket __bpfbox *__select_bucket(struct bpf_htab_inner __bpfbox *htab, u32 hash)
{
	struct bucket __bpfbox *bucket = *unbox(&htab->buckets);
	return &bucket[hash & (*unbox(&htab->n_buckets) - 1)];
}

static inline struct bb_hlist_nulls_head __bpfbox *select_bucket(struct bpf_htab_inner __bpfbox *htab, u32 hash)
{
	return &__select_bucket(htab, hash)->head;
}

static inline int bpf_box_memcmp(const char __bpfbox *s, const char __bpfbox *d, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		char a = *unbox(s);
		char b = *unbox(d);
		if (a > b) return -1;
		else if (a < b) return 1;
		s++; d++;
	}
	return 0;
}

static inline int bpf_box_memcpy(char __bpfbox *d, const char __bpfbox *s, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		*unbox(d) = *unbox(s);
	}
	return 0;
}

/* can be called without bucket lock. it will repeat the loop in
 * the unlikely event when elements moved from one bucket into another
 * while link list is being walked
 */
static struct htab_elem __bpfbox *lookup_nulls_elem_raw(struct bb_hlist_nulls_head __bpfbox *head,
					       u32 hash, void __bpfbox *key,
					       u32 key_size, u32 n_buckets)
{
	struct bb_hlist_nulls_node __bpfbox *n;
	struct htab_elem __bpfbox *l;

again:
	/* bb_hlist_nulls_for_each_entry_rcu(l, n, head, hash_node) */
	/* 	if (*unbox(&l->hash) == hash && !bpf_box_memcmp(&l->key[0], key, key_size)) */
	/* 		return l; */

	bb_hlist_nulls_for_each_entry_rcu(l, n, head, hash_node)
		if (*unbox(&l->hash) == hash && !memcmp(unbox(&l->key[0]), unbox(key), key_size))
			return l;

	if (unlikely(bb_get_nulls_value(n) != (hash & (n_buckets - 1))))
		goto again;

	return NULL;
}

void __bpfbox *__htab_map_lookup_elem(struct bpf_map_inner __bpfbox *map_inner,
					void __bpfbox *key)
{
	struct bpf_htab_inner __bpfbox *inner = box_container_of(map_inner, struct bpf_htab_inner, map_inner);
	struct bb_hlist_nulls_head __bpfbox *head;
	struct htab_elem __bpfbox *l;
	u32 hash, key_size;

	WARN_ON_ONCE(!rcu_read_lock_held() && !rcu_read_lock_trace_held() &&
		     !rcu_read_lock_bh_held());

	key_size = *unbox(&map_inner->key_size);

	hash = htab_map_hash(key, key_size, *unbox(&inner->hashrnd));

	head = select_bucket(inner, hash);

	l = lookup_nulls_elem_raw(head, hash, key, key_size, *unbox(&inner->n_buckets));

	return l;
}

static int htab_lock_bucket(const struct bpf_htab_inner __bpfbox *inner,
			    struct bucket __bpfbox *b, u32 hash,
			    unsigned long *pflags)
{
	unsigned long flags;
	int cpu;
	long lock_v;
	local_t *lock;

	hash = hash & min_t(u32, HASHTAB_MAP_LOCK_MASK, *unbox(&inner->n_buckets) - 1);

	preempt_disable();
	cpu = raw_smp_processor_id();

	/* lockp = unbox(inner->map_locked + cpu); */
	/* lock = unbox(lockp[hash]); */
	lock = unbox(&(*unbox(&(*unbox(&inner->map_locked))[cpu]))[hash]);
	lock_v = local_add_return(1, lock);
	if (unlikely(lock_v != 1)) {
		local_sub(1, lock);
		preempt_enable();
		return -EBUSY;
	}

	raw_spin_lock_irqsave(unbox(&b->raw_lock), flags);
	*pflags = flags;

	return 0;
}

static void htab_unlock_bucket(const struct bpf_htab_inner __bpfbox *inner,
				      struct bucket __bpfbox *b, u32 hash,
				      unsigned long flags)
{
	local_t *lock;
	int cpu;
	hash = hash & min_t(u32, HASHTAB_MAP_LOCK_MASK, *unbox(&inner->n_buckets) - 1);
	cpu = raw_smp_processor_id();
	raw_spin_unlock_irqrestore(unbox(&b->raw_lock), flags);
	lock = unbox(&(*unbox(&(*unbox(&inner->map_locked))[cpu]))[hash]);
	local_sub(1, lock);
	preempt_enable();
}

static struct htab_elem __bpfbox *lookup_elem_raw(struct bb_hlist_nulls_head __bpfbox *head,
						  u32 hash, void __bpfbox *key, u32 key_size)
{
	struct bb_hlist_nulls_node __bpfbox *n;
	struct htab_elem __bpfbox *l;

	/* bb_hlist_nulls_for_each_entry_rcu(l, n, head, hash_node) */
	/* 	if (*unbox(&l->hash) == hash && !bpf_box_memcmp(&l->key[0], key, key_size)) */
	/* 		return l; */
	bb_hlist_nulls_for_each_entry_rcu(l, n, head, hash_node)
		if (*unbox(&l->hash) == hash && !memcmp(unbox(&l->key[0]), unbox(key), key_size))
			return l;

	return NULL;
}

static int check_flags(struct bpf_htab_inner __bpfbox *htab, struct htab_elem __bpfbox *l_old,
		       u64 map_flags)
{
	if (l_old && (map_flags & ~BPF_F_LOCK) == BPF_NOEXIST)
		/* elem already exists */
		return -EEXIST;

	if (!l_old && (map_flags & ~BPF_F_LOCK) == BPF_EXIST)
		/* elem doesn't exist, cannot update it */
		return -ENOENT;

	return 0;
}

static bool fd_htab_map_needs_adjust(const struct bpf_htab_inner __bpfbox *inner)
{
	return *unbox(&(inner->map_inner.map_type)) == BPF_MAP_TYPE_HASH_OF_MAPS &&
	       BITS_PER_LONG == 64;
}

static inline bool htab_is_prealloc(const struct bpf_htab_inner __bpfbox *inner)
{
	return !(*unbox(&inner->map_inner.map_flags) & BPF_F_NO_PREALLOC);
}

static struct htab_elem __bpfbox *alloc_htab_elem(struct bpf_htab_inner __bpfbox *inner,
						  void __bpfbox *key,
					 	  void __bpfbox *value, u32 key_size, u32 hash,
					 	  bool percpu, bool onallcpus,
					 	  struct htab_elem __bpfbox *old_elem)
{
	bool prealloc = htab_is_prealloc(inner);
	struct htab_elem __bpfbox *l_new;
	struct htab_elem __bpfbox **pl_new;

	if (prealloc) {
		if (old_elem) {
			/* if we're updating the existing element,
			 * use per-cpu extra elems to avoid freelist_pop/push
			 */
			int cpu = raw_smp_processor_id();
			pl_new = unbox(*unbox(&inner->extra_elems) + cpu);
			l_new = *pl_new;
			if (*unbox(&inner->map_inner.map_type) == BPF_MAP_TYPE_HASH_OF_MAPS)
				BUG();
			*pl_new = old_elem;
		} else {
			struct bb_pcpu_freelist_node __bpfbox *l;

			l = __bb_pcpu_freelist_pop(&inner->freelist);
			if (!l)
				return (void __bpfbox *) ERR_PTR(-E2BIG);
			l_new = box_container_of(l, struct htab_elem, fnode);
		}
	} else {
		BUG();
	}

	/* bpf_box_memcpy(l_new->key, key, key_size); */
	memcpy(unbox(&l_new->key[0]), unbox(key), key_size);
	if (percpu) {
		BUG();
	} else if (fd_htab_map_needs_adjust(inner)) {
		BUG();
	} else {
		if (*unbox(&inner->map_inner.map_flags) != 0) {
			BUG();
		} else {
			memcpy(unbox(&(l_new->key[0]) + round_up(key_size, 8)), unbox(value),
			       *unbox(&inner->map_inner.value_size));
			/* bpf_box_memcpy(&l_new->key[0] + round_up(key_size, 8), value, */
			/* 	       *unbox(&inner->map_inner.value_size)); */

		}
	}

	*unbox(&l_new->hash) = hash;
	return l_new;
}

static inline void bb_bpf_lru_node_set_ref(struct bb_bpf_lru_node __bpfbox *node)
{
	/* ref is an approximation on access frequency.  It does not
	 * have to be very accurate.  Hence, no protection is used.
	 */
	if (!*unbox(&node->ref))
		*unbox(&node->ref) = 1;
}

int __htab_map_update_elem(struct bpf_map_inner __bpfbox *map_inner, void __bpfbox *key,
				  void __bpfbox *value, u64 map_flags)
{
	struct bpf_htab_inner __bpfbox *inner = \
		box_container_of(map_inner, struct bpf_htab_inner, map_inner);
	struct htab_elem __bpfbox *l_old;
	struct htab_elem __bpfbox *l_new = NULL;
	struct bb_hlist_nulls_head __bpfbox *head;
	unsigned long flags;
	struct bucket __bpfbox *b;
	u32 key_size, hash;
	int ret;

	if (unlikely((map_flags & ~BPF_F_LOCK) > BPF_EXIST))
		/* unknown flags */
		return -EINVAL;

	WARN_ON_ONCE(!rcu_read_lock_held() && !rcu_read_lock_trace_held() &&
		     !rcu_read_lock_bh_held());

	key_size = *unbox(&map_inner->key_size);

	hash = htab_map_hash(key, key_size, *unbox(&inner->hashrnd));

	b = __select_bucket(inner, hash);
	head = &b->head;

	if (unlikely(map_flags & BPF_F_LOCK)) {
		BUG();
	}

	ret = htab_lock_bucket(inner, b, hash, &flags);
	if (ret) {
		return ret;
	}

	l_old = lookup_elem_raw(head, hash, key, key_size);

	ret = check_flags(inner, l_old, map_flags);
	if (ret)
		goto err;

	if (unlikely(l_old && (map_flags & BPF_F_LOCK))) {
		BUG();
	}

	l_new = alloc_htab_elem(inner, key, value, key_size, hash, false, false,
				l_old);
	if (IS_ERR(l_new)) {
		/* all pre-allocated elements are in use or memory exhausted */
		ret = PTR_ERR(l_new);
		goto err;
	}

	/* add new element to the head of the list, so that
	 * concurrent search will find it before old elem
	 */
	bb_hlist_nulls_add_head_rcu(box(&l_new->hash_node), head);
	if (l_old) {
		bb_hlist_nulls_del_rcu(box(&l_old->hash_node));
		if (!htab_is_prealloc(inner)) {
			BUG();
		}
	}
	ret = 0;
err:
	htab_unlock_bucket(inner, b, hash, flags);
	return ret;
}

void __bpfbox *__htab_lru_map_lookup_elem(struct bpf_map_inner __bpfbox *map_inner,
					  void __bpfbox *key)
{
	struct htab_elem __bpfbox *l = __htab_map_lookup_elem(map_inner, key);

	if (l) {
		bb_bpf_lru_node_set_ref(&l->lru_node);
		return &l->key[0] + round_up(*unbox(&map_inner->key_size), 8);
	}

	return NULL;
}


static struct htab_elem __bpfbox *prealloc_lru_pop(struct bpf_htab_inner __bpfbox *inner, void __bpfbox *key,
					  u32 hash)
{
	struct bb_bpf_lru_node __bpfbox *node = bb_bpf_lru_pop_free(&inner->lru, hash);
	struct htab_elem __bpfbox *l;

	if (node) {
		l = box_container_of(node, struct htab_elem, lru_node);
		memcpy(unbox(l->key), unbox(key), *unbox(&inner->map_inner.key_size));
		return l;
	}

	return NULL;
}

static void htab_lru_push_free(struct bpf_htab_inner __bpfbox *inner,
			       struct htab_elem __bpfbox *elem)
{
	bb_bpf_lru_push_free(&inner->lru, &elem->lru_node);
}


int __htab_lru_map_update_elem(struct bpf_map_inner __bpfbox *map_inner,
				      void __bpfbox *key, void __bpfbox *value,
				      u64 map_flags)
{
	struct bpf_htab_inner __bpfbox *inner = \
		box_container_of(map_inner, struct bpf_htab_inner, map_inner);
	struct htab_elem __bpfbox *l_new, *l_old = NULL;
	struct bb_hlist_nulls_head __bpfbox *head;
	unsigned long flags;
	struct bucket __bpfbox *b;
	u32 key_size, hash;
	int ret;

	if (unlikely(map_flags > BPF_EXIST))
		/* unknown flags */
		return -EINVAL;

	WARN_ON_ONCE(!rcu_read_lock_held() && !rcu_read_lock_trace_held() &&
		     !rcu_read_lock_bh_held());

	key_size = *unbox(&map_inner->key_size);

	hash = htab_map_hash(key, key_size, *unbox(&inner->hashrnd));

	b = __select_bucket(inner, hash);
	head = &b->head;

	/* For LRU, we need to alloc before taking bucket's
	 * spinlock because getting free nodes from LRU may need
	 * to remove older elements from htab and this removal
	 * operation will need a bucket lock.
	 */
	l_new = prealloc_lru_pop(inner, key, hash);
	if (!l_new)
		return -ENOMEM;

	if (*unbox(&inner->map_inner.map_flags) != 0) {
		BUG();
	} else {
		memcpy(unbox(&(l_new->key[0]) + round_up(key_size, 8)), unbox(value),
			*unbox(&inner->map_inner.value_size));
	}


	ret = htab_lock_bucket(inner, b, hash, &flags);
	if (ret)
		return ret;

	l_old = lookup_elem_raw(head, hash, key, key_size);

	ret = check_flags(inner, l_old, map_flags);
	if (ret)
		goto err;

	/* add new element to the head of the list, so that
	 * concurrent search will find it before old elem
	 */
	bb_hlist_nulls_add_head_rcu(&l_new->hash_node, head);
	if (l_old) {
		bb_bpf_lru_node_set_ref(&l_new->lru_node);
		bb_hlist_nulls_del_rcu(&l_old->hash_node);
	}
	ret = 0;

err:
	htab_unlock_bucket(inner, b, hash, flags);

	if (ret)
		htab_lru_push_free(inner, l_new);
	else if (l_old)
		htab_lru_push_free(inner, l_old);

	return ret;
}

