#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "RC5.h"

#define COLOR_GREEN "\033[0;32m"
#define COLOR_RED "\033[0;31m"
#define COLOR_RESET "\033[0m"

// Function to print test results with colors
void print_result(const char* description, uint32_t* expected, uint32_t* actual) {
    if (memcmp(expected, actual, sizeof(uint32_t) * 2) == 0) {
        printf(COLOR_GREEN "[PASS] %s: Expected = 0x%08x 0x%08x, Got = 0x%08x 0x%08x\n" COLOR_RESET,
               description, expected[0], expected[1], actual[0], actual[1]);
    } else {
        printf(COLOR_RED "[FAIL] %s: Expected = 0x%08x 0x%08x, Got = 0x%08x 0x%08x\n" COLOR_RESET,
               description, expected[0], expected[1], actual[0], actual[1]);
    }
}

int main() {
    struct {
        uint32_t key[KEY_WORD_SIZE];
        uint32_t plaintext[2];
        uint32_t expected_ciphertext[2];
    } __attribute__((aligned(32))) tests[] = {
        {{0x00000000, 0x00000000, 0x00000000, 0x00000000}, {0x00000000, 0x00000000}, {0xEEDBA521, 0x6D8F4B15}},
        {{0x19465F91, 0x51B241BE, 0x01A55563, 0x91CEA910}, {0xEEDBA521, 0x6D8F4B15}, {0xAC13C0F7, 0x52892B5B}},
        {{0xE7483378, 0x2F0FEB5A, 0xBB69B1D7, 0x8767C18D}, {0xAC13C0F7, 0x52892B5B}, {0xB7B3422F, 0x92FC6903}},
        {{0x13DB49DC, 0x4F58A575, 0x13B48564, 0xAF2BF1B5}, {0xB7B3422F, 0x92FC6903}, {0xB278C165, 0xCC97D184}},
        {{0x49F16952, 0x15A01BD4, 0x4D579724, 0x2531157F}, {0xB278C165, 0xCC97D184}, {0x15E444EB, 0x249831DA}}};

    for (int i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        uint32_t scheduled_keys[SCHEDULE_TABLE_WORD_SIZE];
        uint32_t data[2];
        data[0]= tests[i].plaintext[0];
        data[1]= tests[i].plaintext[1];

        rc5_key_schedule(tests[i].key, scheduled_keys);
        rc5_encrypt(data, scheduled_keys);

        char description[50];
        sprintf(description, "Test #%d Encryption", i + 1);
        print_result(description, tests[i].expected_ciphertext, data);

        rc5_decrypt(data, scheduled_keys);
        sprintf(description, "Test #%d Decryption", i + 1);
        print_result(description, tests[i].plaintext, data);
    }

    return 0;
}
