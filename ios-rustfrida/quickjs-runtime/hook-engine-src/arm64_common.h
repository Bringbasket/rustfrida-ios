/*
 * arm64_common.h - Shared macros and inline functions for ARM64 code generation
 *
 * Used by arm64_writer.c and arm64_relocator.c to avoid duplication.
 */

#ifndef ARM64_COMMON_H
#define ARM64_COMMON_H

#include <stdint.h>

/* Extract bits [hi:lo] from x */
#define GET_BITS(x, hi, lo) (((x) >> (lo)) & ((1u << ((hi) - (lo) + 1)) - 1))

/* Replace bits [hi:lo] in orig with v */
#define SET_BITS(orig, hi, lo, v) \
    (((orig) & ~(((1u << ((hi) - (lo) + 1)) - 1) << (lo))) | \
     (((v) & ((1u << ((hi) - (lo) + 1)) - 1)) << (lo)))

/* Sign extend a value */
static inline int64_t sign_extend(uint64_t value, int bits) {
    int shift = 64 - bits;
    return ((int64_t)(value << shift)) >> shift;
}

/* Check if value fits in signed range */
static inline int fits_signed(int64_t v, int bits) {
    int64_t min_val = -(1LL << (bits - 1));
    int64_t max_val = (1LL << (bits - 1)) - 1;
    return v >= min_val && v <= max_val;
}

/* Check if value fits in unsigned range */
static inline int fits_unsigned(uint64_t v, int bits) {
    return v < (1ULL << bits);
}

#endif /* ARM64_COMMON_H */
