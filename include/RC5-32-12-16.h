/**
 * @file       rc5_32_12_16.h
 * @brief      RC5 encryption and decryption functions with key expansion.
 * @details    This file provides the implementation of the RC5 block cipher 
 *             with 32-bit words, 12 rounds, and a 16-byte key. It includes 
 *             key expansion, encryption, and decryption functions optimized 
 *             for performance in embedded systems.
 *             
 *             The key expansion routine expands a 128-bit key into a 
 *             schedule for 12 rounds of encryption. The encryption and 
 *             decryption functions implement the RC5 algorithm using 
 *             rotate-left (ROTL) and rotate-right (ROTR) operations, with 
 *             efficient key mixing and data transformations.
 *
 * @copyright (C) 2025, Manoel Augusto de Souza Serafim
 *             All rights reserved.
 *
 * @author     Manoel Serafim
 * @email      manoel.serafim@proton.me
 * @date       2025-01-03
 * @github     https://github.com/manoel-serafim
 *
 */

#ifndef RC5_32_12_16_H
#define RC5_32_12_16_H

//NOLINTNEXTLINE(hicpp-deprecated-headers, modernize-deprecated-headers)
#include <stdint.h>

enum {
    KEY_WORD_SIZE = 4U, // BYTES
    NUMBER_OF_ROUNDS = 12U,
    SCHEDULE_TABLE_WORD_SIZE = 26U, // 2*(NUMBER_OF_ROUNDS + 1)
};

void rc5_encrypt(uint32_t* data, uint32_t key[KEY_WORD_SIZE]);
void rc5_decrypt(uint32_t* data, uint32_t key[KEY_WORD_SIZE]);

#endif // RC5_32_12_16_H