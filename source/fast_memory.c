#include "fast_memory.h"
#include <stdint.h>


void fast_memcpy(void * const restrict dest, const void * const restrict src, uint32_t n_bytes_to_cpy)
{
	register uint8_t *dest_register = (uint8_t *)dest;
	register const uint8_t *src_register = (uint8_t *)src;

    //NOLINTNEXTLINE(altera-unroll-loops)
	while (n_bytes_to_cpy) {
		*dest_register = *src_register;
        ++dest_register;
        ++src_register;
		--n_bytes_to_cpy;
	}
}

void fast_memset(void * const dest, const int8_t value, uint32_t n_bytes_to_set)
{
	register int8_t *dest_register = (int8_t *) dest;

	//NOLINTNEXTLINE(altera-unroll-loops)
	while (n_bytes_to_set) {
		*dest_register = value;
		++dest_register;
		--n_bytes_to_set;
	}

}

