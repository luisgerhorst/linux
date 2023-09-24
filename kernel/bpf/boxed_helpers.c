#include <linux/kernel.h>
#include <linux/bpf.h>
#include <linux/bpfbox.h>
#include "hashtab.h"

#define box_container_of(ptr, type, member) ({				\
	void __bpfbox *__mptr = (void __bpfbox *)(ptr);			\
	static_assert(__same_type(*(ptr), ((type *)0)->member) ||	\
		      __same_type(*(ptr), void),			\
		      "pointer type mismatch in container_of()");	\
	((type __bpfbox *)(__mptr - offsetof(type, member))); })

register void *base asm ("r12");
#define unbox(p)	\
({			\
	BPFBOX_CHECK_VALID((p));	\
	(typeof(*(p)) __kernel __force *)(base + ((unsigned long)(p) & 0xffffffff)); \
})

#define box(p)	\
({		\
	void __bpfbox *ptr;			\
	ptr = (unsigned long)(p) - base;	\
	BPFBOX_CHECK_VALID(ptr);		\
	(typeof(*(p)) __bpfbox *) ptr;		\
})



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
	u32 a, b, c;
	const u8 __bpfbox *k = key;

	/* Set up the internal state */
	a = b = c = JHASH_INITVAL + length + initval;

	/* All but the last block: affect some 32 bits of (a,b,c) */
	while (length > 12) {
		a += __get_unaligned_cpu32(unbox(k));
		b += __get_unaligned_cpu32(unbox(k + 4));
		c += __get_unaligned_cpu32(unbox(k + 8));
		__jhash_mix(a, b, c);
		length -= 12;
		k += 12;
	}
	/* Last block: affect all 32 bits of (c) */
	switch (length) {
	case 12: c += (u32)*unbox(&k[11])<<24;	fallthrough;
	case 11: c += (u32)*unbox(&k[10])<<16;	fallthrough;
	case 10: c += (u32)*unbox(&k[9])<<8;	fallthrough;
	case 9:  c += *unbox(&k[8]);		fallthrough;
	case 8:  b += (u32)*unbox(&k[7])<<24;	fallthrough;
	case 7:  b += (u32)*unbox(&k[6])<<16;	fallthrough;
	case 6:  b += (u32)*unbox(&k[5])<<8;	fallthrough;
	case 5:  b += *unbox(&k[4]);		fallthrough;
	case 4:  a += (u32)*unbox(&k[3])<<24;	fallthrough;
	case 3:  a += (u32)*unbox(&k[2])<<16;	fallthrough;
	case 2:  a += (u32)*unbox(&k[1])<<8;	fallthrough;
	case 1:  a += *unbox(&k[0]);
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

static inline struct hlist_nulls_head *select_bucket(struct bpf_htab_inner __bpfbox *htab, u32 hash)
{
	return unbox(&__select_bucket(htab, hash)->head);
}

/* can be called without bucket lock. it will repeat the loop in
 * the unlikely event when elements moved from one bucket into another
 * while link list is being walked
 */
static struct htab_elem *lookup_nulls_elem_raw(struct hlist_nulls_head *head,
					       u32 hash, void *key,
					       u32 key_size, u32 n_buckets)
{
	struct hlist_nulls_node *n;
	struct htab_elem *l;

again:
	hlist_nulls_for_each_entry_rcu(l, n, head, hash_node)
		if (l->hash == hash && !memcmp(&l->key, key, key_size))
			return l;

	if (unlikely(get_nulls_value(n) != (hash & (n_buckets - 1))))
		goto again;

	return NULL;
}

void __bpfbox *__htab_map_lookup_elem(struct bpf_map_inner __bpfbox *map_inner,
					void __bpfbox *key)
{
	struct bpf_htab_inner __bpfbox *inner = box_container_of(map_inner, struct bpf_htab_inner, map_inner);
	struct hlist_nulls_head *head;
	struct htab_elem *l;
	u32 hash, key_size;

	WARN_ON_ONCE(!rcu_read_lock_held() && !rcu_read_lock_trace_held() &&
		     !rcu_read_lock_bh_held());

	key_size = *unbox(&map_inner->key_size);

	hash = htab_map_hash(key, key_size, *unbox(&inner->hashrnd));

	head = select_bucket(inner, hash);

	l = lookup_nulls_elem_raw(head, hash, unbox(key), key_size, *unbox(&inner->n_buckets));

	if (l == NULL)
		return NULL;
	else
		return bpf_box_or_null_ptr(l);
}
