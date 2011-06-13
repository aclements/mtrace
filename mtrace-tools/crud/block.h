#include <sys/mman.h>

struct block_link {
	struct block_link *next;
};

struct block_pool {
	uint8_t *start;
	uint8_t *cur;
	uint8_t *end;
	size_t bsize;
	unsigned int nb;

	struct block_link *free;
};

static inline void balloc_init(size_t bsize, unsigned int nb, struct block_pool *bp)
{
	void *ptr = mmap(NULL, bsize * nb, PROT_READ|PROT_WRITE, 
			 MAP_SHARED|MAP_ANONYMOUS, 0, 0);
	if (ptr == MAP_FAILED)
		edie("balloc_init: mmap");

	bp->start = (uint8_t *)ptr;
	bp->cur = bp->start;
	bp->end = bp->start + (bsize * nb);
	bp->bsize = bsize;
	bp->nb = nb;
	bp->free = NULL;
}



static inline void *balloc(struct block_pool *bp)
{
	struct block_link *link;

	if (bp->free == NULL) {
		if (bp->cur == bp->end) {
			void *ptr;
			ptr = mremap(bp->start, bp->bsize * bp->nb,
				     2 * bp->bsize * bp->nb,
				     0);
			if (ptr == MAP_FAILED)
				edie("balloc: mremap");
			bp->nb *= 2;
			bp->end = bp->start + (bp->bsize * bp->nb);
		}
		bp->free = (struct block_link *) bp->cur;
		bp->free->next = NULL;
		bp->cur += bp->bsize;
	}

	link = bp->free;
	bp->free = link->next;
	return (void *)link;
}

static inline void bfree(struct block_pool *bp, void *b)
{
	struct block_link *link;

	link = (struct block_link *)b;
	link->next = bp->free;
	bp->free = link;
}
