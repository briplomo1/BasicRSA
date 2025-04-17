//
// Created by bripl on 4/8/2025.
//

#ifndef RSA_H
#define RSA_H

#include <cstdint>
#include <string>
#include <iostream>


struct RSAKey {
    uint64_t exponent;
    uint64_t n;
};

class RSA {
    static constexpr int MAX_KEY_LENGTH = 64;
    static constexpr int DEFAULT_E = 17;

public:

    RSA();

    ~RSA();

    /**
     * Perform encryption using a key on a given plain integer as data to encrypt.
     * @param key The public {@link RSAKey} used for encrypting data
     * @param plain The plain integer which is the data to be encrypted
     * @return The encrypted data using the public key RSA encryption,
     */
    static uint64_t encrypt(RSAKey key, uint64_t plain);

    /**
     * Perform decryption on encrypted data using a private key.
     * @param key The private {@link RSAKey} used to decrypt the data
     * @param encrypted The encrypted data
     * @return The decrypted data using RSA decryption
     */
    static uint64_t decrypt(RSAKey key, uint64_t encrypted);

    /**
    * Generates RSA keys given a desired length in bits. Will generate keys making use of all bits.
    * @param bitLength
    * @param useDefaultE A bool flag to use the default value for e or generate a random e instead
    */
    static std::pair<RSAKey, RSAKey> generateKeys(uint64_t bitLength=MAX_KEY_LENGTH, bool useDefaultE=false);

private:

    /**
    * Calculates the modular inverse x from a and phi such that a*x + phi*y = 1 if a and m are coprime.
    * Uses the extended euclidian algorithm.
    * @param a The number who's inverse we calculate
    * @param phi The modulus used in calculating the inverse
    * @return Returns the modular inverse
    */
    static uint64_t modInverse(uint64_t a, uint64_t phi);

    /**
    * Computes the gcd of two numbers a and b.
     * @param a The first number
    * @param b The second number
     * @return The gcd of a and b. Will be 1 if a and b are coprime.
     */
    static uint64_t gcd(uint64_t a, uint64_t b);

    /**
    * Generate a prime nuber of given bit length. Will generate random numbers until a prime is verified.
    * @param length The bit length of the number to generate
    * @return An unsigned 64 bit long prime number
    */
    static uint64_t generatePrime(uint64_t length);

    /**
     * Check that a given number is prime by checking that n mod X == 0 for all odd numbers x in [5, sqrt(n)].
     * @param number The number whose primality is being tested
     * @return Boolean indicating if the number is prime
     */
    static bool isPrime(uint64_t number);

    /**
     * Generates a random number within a range of two given integers.
     * @param min The minimum of values to be generated
     * @param max The maximum of values to be generated
     * @return A random unsigned integer
     */
    static uint64_t generateNumber(uint64_t min, uint64_t max);

    /**
     * Perform modular exponentiation by a given modulus using unsigned 64-bit integer
     * @param base The base number
     * @param exp The exponent
     * @param modulus The number to modulus by. Defaults to {@link UINT32_MAX} if not given.
     * @return The resulting unsigned 64 integer of base to the power of exp.
     */
    static uint64_t pow_uint64(uint64_t base, uint64_t exp, uint64_t modulus=UINT64_MAX);

    /**
     * Performs modular multiplication on unsigned 64-bit integers returning a new 64-bit integer.
     * Prevents overflow while allowing use of all 64 bits. Will throw error if operands are larger than 32 bits.
     * @param a The first number to multiply. Must be less than {@link UINT32_MAX}.
     * @param b The second number to multiply. Must be less than {@link UINT32_MAX}.
     * @param modulus The modulus. Will default to {@link UINT64_MAX} if no modulus is given.
     * @return The product of a and b modulus mod if mod is given.
     */
    static uint64_t mul_uint64(__uint128_t a, uint64_t b, uint64_t modulus=UINT64_MAX);

};


#endif //RSA_H
