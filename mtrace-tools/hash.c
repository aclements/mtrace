#include <stdint.h>
#include "hash.h"

/* 
 * hash function from: http://burtleburtle.net/bob/hash/evahash.html 
*/

#define mix64(a,b,c) \
{ \
        a -= b; a -= c; a ^= (c>>43); \
        b -= c; b -= a; b ^= (a<<9); \
        c -= a; c -= b; c ^= (b>>8); \
        a -= b; a -= c; a ^= (c>>38); \
        b -= c; b -= a; b ^= (a<<23); \
        c -= a; c -= b; c ^= (b>>5); \
        a -= b; a -= c; a ^= (c>>35); \
        b -= c; b -= a; b ^= (a<<49); \
        c -= a; c -= b; c ^= (b>>11); \
        a -= b; a -= c; a ^= (c>>12); \
        b -= c; b -= a; b ^= (a<<18); \
        c -= a; c -= b; c ^= (b>>22); \
}

uint64_t bb_hash(register uintptr_t *k, register uint64_t length)
{
	register uint64_t a, b, c, len;

	/* Set up the internal state */
	len = length;
	a = b = 0xdeadbeef;		/* the previous hash value */
	c = 0x9e3779b97f4a7c13LL;	/* the golden ratio; an arbitrary value */

	while (len >= 3) {
		a += k[0];
		b += k[1];
		c += k[2];
		mix64(a, b, c);
		k += 3;
		len -= 3;
	}
	
	c += length;
	switch (len) {		/* all the case statements fall through */
	case 2:
		b += k[1];
	case 1:
		a += k[0];
	default:
		;
	}
	
	mix64(a, b, c);
	return c;

}
