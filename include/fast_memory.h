/**
 * @file       fast_memory.h
 * @brief      High-performance memory manipulation functions.
 * @details    This file provides optimized implementations of memory copy 
 *             and memory set operations tailored for performance-critical 
 *             applications. The `fast_memcpy` and `fast_memset` functions 
 *             are designed to work with raw memory buffers, avoiding 
 *             overhead from standard library implementations and allowing 
 *             fine-grained control over the operations.
 *
 * @copyright (C) 2024, Manoel Augusto de Souza Serafim
 *             All rights reserved.
 *
 * @author     Manoel Serafim
 * @email      manoel.serafim@proton.me
 * @date       2024-12-25
 * @github     https://github.com/manoel-serafim
 *
 */

#ifndef FAST_MEMORY_H
#define FAST_MEMORY_H

#include <stdint.h>

void fast_memcpy(void * restrict dest, const void * restrict src, uint32_t n_bytes_to_cpy);
void fast_memset(void * dest, int8_t value, uint32_t n_bytes_to_set);

#endif // FAST_MEMORY_H
