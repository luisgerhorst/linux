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
	BB_WRITE_ONCE(n->pprev, LIST_POISON2);
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

static struct htab_elem __bpfbox *alloc_htab_elem(struct bpf_htab *htab, void __bpfbox *key,
					 void __bpfbox *value, u32 key_size, u32 hash,
					 bool percpu, bool onallcpus,
					 struct htab_elem __bpfbox *old_elem)
{
	struct bpf_htab_inner __bpfbox *inner = box(htab_inner(htab));
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
			copy_map_value(&htab->map,
				(char*)unbox(&l_new->key) + round_up(key_size, 8),
				unbox(value));
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

static void free_htab_elem(struct bpf_htab *htab, struct htab_elem *l)
{
	BUG();
	if (htab_is_prealloc(box(htab_inner(htab)))) {
		/* __pcpu_freelist_push(&htab_inner(htab)->freelist, &l->fnode); */
	} else {
		BUG();
	}
}

int __htab_map_update_elem(struct bpf_map_inner __bpfbox *map_inner, void __bpfbox *key,
				  void __bpfbox *value, u64 map_flags)
{
	struct bpf_htab_inner __bpfbox *inner = \
		box_container_of(map_inner, struct bpf_htab_inner, map_inner);
	struct bpf_htab *htab = *unbox(&inner->htab);
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

	l_new = alloc_htab_elem(htab, key, value, key_size, hash, false, false,
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
			free_htab_elem(htab, unbox(l_old));
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
		bpf_lru_node_set_ref(unbox(&l->lru_node));
		return &l->key[0] + round_up(*unbox(&map_inner->key_size), 8);
	}

	return NULL;
}

