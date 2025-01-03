#include "RC5-32-12-16.h"
#include <stdint.h>

static const uint8_t BIT32_LEN = 32U;
static inline uint32_t ROT32L(const uint32_t value,
                                  const uint8_t rot_amount)
{
    return (value << rot_amount) | (value >> (uint8_t)(BIT32_LEN - rot_amount));
}

static inline uint32_t ROT32R(const uint32_t value,
                                  const uint8_t rot_amount)
{
    //NOLINTNEXTLINE(*)
    return (value >> rot_amount) | (value << (uint8_t)(BIT32_LEN - rot_amount));
}

/**
 * @brief Key Expansion
 * @details The key-expansion routine expands the user's secret key K to fill the expanded
 *          key array S, so that S resembles an array of t = 2(r + 1) random binary words
 *          determined by K. The key expansion algorithm uses two "magic constants," and
 *          consists of three simple algorithmic parts.
 * 
 * @param[inout] key 
 * @param[inout] key_schedule
 */
//NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
static void key_schedule(uint32_t key[KEY_WORD_SIZE] , uint32_t key_schedule[SCHEDULE_TABLE_WORD_SIZE])
{

    /**
     * @brief Definition of the Magic Constants
     * @details The key-expansion algorithm uses two
     *          word-sized binary constants Pw and Qw They are defined for arbitrary w as
     *          follows:
     *          P32 = 101101111110000i0i01000101i00011 = b7e15163
     *          Q32 = 10011110001101110111100110111001 = 9e3779b9
     */
    static const uint32_t NUMS_MAGIC_P32 = 0xB7e15163U; //Nothing Up My Sleve constant
    static const uint32_t NUMS_MAGIC_Q32 = 0x9E3779B9U; //Nothing Up My Sleve constant
    
    /**
     * @brief Converting the Secret Key from Bytes to LE Words
     * @details Already done in key definition
     */

    /**
     * @brief Initializing the Array S
     * @details The second algorithmic step of key expansion is
     *          to initialize array S to a particular fixed (key-independent) pseudo-random bit
     *          pattern, using an arithmetic progression modulo 2^w determined by the "magic
     *          constants" Pw and Qw. Since Qw is odd, the arithmetic progression has period
     *          2^w. 
     */
    key_schedule[0U] = NUMS_MAGIC_P32;

    uint8_t schedule_index = 1U;
    //NOLINTNEXTLINE(altera-unroll-loops)
    do
    {
        key_schedule[schedule_index] = key_schedule[schedule_index-1U] + NUMS_MAGIC_Q32;
        ++schedule_index;
        key_schedule[schedule_index] = key_schedule[schedule_index-1U] + NUMS_MAGIC_Q32;
        ++schedule_index;
        key_schedule[schedule_index] = key_schedule[schedule_index-1U] + NUMS_MAGIC_Q32;
        ++schedule_index;
        key_schedule[schedule_index] = key_schedule[schedule_index-1U] + NUMS_MAGIC_Q32;
        ++schedule_index;
    }//NOLINTNEXTLINE(altera-id-dependent-backward-branch)
    while(schedule_index < (uint8_t)SCHEDULE_TABLE_WORD_SIZE);

    /**
     * @brief Mixing in the Secret Key
     * @details The third algorithmic step of key expansion is
     *          to mix in the user's secret key in three passes over the arrays S and L. More
     *          precisely, due to the potentially different sizes of S and L, the larger array will
     *          be processed three times, and the other may be handled more times.
     *          c = 4(words in key), t = 26(words in schedule)
     */
    schedule_index =0U;
    uint8_t key_index = 0U;
    uint32_t variable_A = 0U;
    uint32_t variable_B = 0U;
    uint8_t counter = 0U;

    //NOLINTNEXTLINE(altera-unroll-loops)
    do
    {
        key_schedule[schedule_index] = ROT32L(key_schedule[schedule_index] + variable_A + variable_B, 3U);
        variable_A = key_schedule[schedule_index];

        key[key_index] = ROT32L(key[key_index]+ variable_A + variable_B, variable_A+variable_B);
        variable_B = key[key_index];

        schedule_index = (schedule_index+1)%SCHEDULE_TABLE_WORD_SIZE;
        key_index = (key_index+1U) & 0x3U;

        key_schedule[schedule_index] = ROT32L(key_schedule[schedule_index] + variable_A + variable_B, 3U);
        variable_A = key_schedule[schedule_index];

        key[key_index] = ROT32L(key[key_index]+ variable_A + variable_B, variable_A+variable_B);
        variable_B = key[key_index];

        schedule_index = (schedule_index+1)%SCHEDULE_TABLE_WORD_SIZE;
        key_index = (key_index+1U) & 0x3U;

        key_schedule[schedule_index] = ROT32L(key_schedule[schedule_index] + variable_A + variable_B, 3U);
        variable_A = key_schedule[schedule_index];

        key[key_index] = ROT32L(key[key_index]+ variable_A + variable_B, variable_A+variable_B);
        variable_B = key[key_index];

        schedule_index = (schedule_index+1)%SCHEDULE_TABLE_WORD_SIZE;
        key_index = (key_index+1U) & 0x3U;

        ++counter;
    } while (counter < SCHEDULE_TABLE_WORD_SIZE);
    
    


}

/**
 * @brief Encryption
 * @details We assume that the input block is given in two w-bit registers A and B. We
 *          also assume that key-expansion has already been performed, so that the array
 *          S[0...t - 1] has been computed. Here is the encryption algorithm in pseudo-code
 * 
 * @param[inout] data 
 * @param[in] key
 */
//NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void rc5_encrypt( uint32_t* const data, uint32_t key[KEY_WORD_SIZE])
{
    
    uint32_t scheduled_keys[SCHEDULE_TABLE_WORD_SIZE];

    key_schedule(key, scheduled_keys);
    
    register uint32_t variable_A = data[0] + scheduled_keys[0];
    register uint32_t variable_B = data[1] + scheduled_keys[0];

    uint16_t index_shifted = 2U;
    uint8_t index = 1U;

    //NOLINTNEXTLINE(altera-unroll-loops)
    do
    {

        variable_A = ROT32L((variable_A ^ variable_B), variable_B) + scheduled_keys[index_shifted];
        variable_B = ROT32L((variable_B ^ variable_A), variable_A) + scheduled_keys[index_shifted + 1];

        ++index;
        index_shifted = index << 1U;
    }
    while(index <= NUMBER_OF_ROUNDS);

    data[0] = variable_A;
    data[1] = variable_B;
}

/**
 * @brief Decryption
 * @details The decryption routine is easily derived from the encryption routine
 * 
 * @param[inout] data 
 * @param[in] key
 */
//NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void rc5_decrypt( uint32_t* const data, uint32_t key[KEY_WORD_SIZE])
{
    
    uint32_t scheduled_keys[SCHEDULE_TABLE_WORD_SIZE];

    key_schedule(key, scheduled_keys);
    
    register uint32_t variable_A = 0U;
    register uint32_t variable_B = 0U;
    uint16_t index_shifted = (uint16_t)NUMBER_OF_ROUNDS >> 1U;
    uint8_t index = NUMBER_OF_ROUNDS;

    //NOLINTNEXTLINE(altera-unroll-loops)
    do
    {
        variable_B = ROT32R((variable_B - scheduled_keys[index_shifted+1]), variable_A) ^ variable_A;
        variable_A = ROT32R((variable_A - scheduled_keys[index_shifted]), variable_B) ^ variable_B;
        
        --index;
        index_shifted = index >> 1U;
    }
    while(index >= 1);

    variable_A = variable_A - scheduled_keys[0];
    variable_B = variable_B - scheduled_keys[1];

    data[0] = variable_A;
    data[1] = variable_B;

}