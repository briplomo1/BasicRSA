//
// Created by bripl on 4/8/2025.
//

#ifndef RSA_H
#define RSA_H

#include <atomic>
#include <cstdint>
#include <string>
#include "BigInt.h"
#include <iostream>
#include <memory>
#include <thread>

namespace RSAEncryption {


    struct RSAKey {
         BigInt exponent;
         BigInt n;
    };

    class RSA {
        static constexpr int DEFAULT_KEY_LENGTH = 1024;
        static constexpr int DEFAULT_E = 65537;


    public:

        RSA();

        ~RSA();

        /**
         * Perform encryption using a key on a given plain integer as data to encrypt.
         * @param key The public {@link RSAKey} used for encrypting data
         * @param plain The plain integer which is the data to be encrypted
         * @return The encrypted data using the public key RSA encryption,
         */
        static BigInt encrypt(const RSAKey& key, const BigInt& plain);

        /**
         * Perform decryption on encrypted data using a private key.
         * @param key The private {@link RSAKey} used to decrypt the data
         * @param encrypted The encrypted data
         * @return The decrypted data using RSA decryption
         */
        static BigInt decrypt(const RSAKey& key, const BigInt& encrypted);

        /**
        * Generates RSA keys given a desired length in bits. Will generate keys making use of all bits.
        * @param bitLength
        * @param useDefaultE A bool flag to use the default value for e or generate a random e instead
        */
        static std::pair<RSAKey, RSAKey> generateKeys(size_t bitLength = DEFAULT_KEY_LENGTH, bool useDefaultE = true);

    private:

        /**
        * Calculates the modular inverse x from a and phi such that a*x + phi*y = 1 if a and m are coprime.
        * Uses the extended euclidian algorithm.
        * @param a The number who's inverse we calculate
        * @param phi The modulus used in calculating the inverse
        * @return Returns the modular inverse
        */
        static BigInt modInverse(BigInt a, BigInt phi);

        /**
        * Computes the gcd of two numbers a and b.
         * @param a The first number
        * @param b The second number
         * @return The gcd of a and b. Will be 1 if a and b are coprime.
         */
        static BigInt gcd(const BigInt& a, const BigInt& b);

        /**
        * Generate a prime nuber of given bit length. Will generate random numbers until a prime is verified.
        * @param length The bit length of the number to generate
        * @param prime
        * @param exitFlag
        * @param tryCount
        */
        static void generatePrime(size_t length, const std::shared_ptr<BigInt>& prime, std::atomic<bool>& exitFlag, std::atomic<int>& tryCount);

        /**
         * Check that a given number is prime by checking that n mod X == 0 for all odd numbers x in [5, sqrt(n)].
         * @param number The number whose primality is being tested
         * @return Boolean indicating if the number is prime
         */
        static bool isPrime(const BigInt& number);
    };
}
#endif //RSA_H
