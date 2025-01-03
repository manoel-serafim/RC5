# RC5
This project implements a blazing-fast version of the RC5-32/12/16 encryption algorithm in C. RC5 is a lightweight, highly parameterized, and efficient block cipher designed by Ronald Rivest. It supports a variety of word sizes, key sizes, and number of rounds. This implementation specifically targets the 32-bit word size, 12 rounds, and 16-byte (128-bit) keys.

Even if this is an awesome, statically allocated, performance oriented implementation, rc5 includes predictable subkeys from its weak key schedule, susceptibility to differential cryptanalysis exploiting predictable data differences, linear cryptanalysis targeting correlations in the round function, and related-key attacks exploiting inadequate key randomization. 

See:
 “On Differential and Linear Cryptanalysis of the RC5 Encryption Algorithm” (Advances in Cryptology—CRYPTO ’95 Proceedings, Springer Verlag, 1995, pp. 445–454); L.R. Knudsen and W. Meier, “Improved Differential Attacks on RC5” (Advances in Cryptology — CRYPTO ’96 Proceedings, Springer-Verlag, 1996, pp. 216–228); and A.A. Selcuk, “New Results in Linear Cryptanalysis of RC5” (Fast 14
Schneier A Self-Study Course in Block-Cipher Cryptanalysis Software Encryption, 5th International Workshop Proceedings, Springer-Verlag, 1998, pp. 1–16)

This implementation was developed as an opportunity to explore and analyze its vulnerabilities, serving as a practical exercise to enhance my skills as a cryptanalyst. 
