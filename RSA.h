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
    static constexpr int MAX_KEY_LENGTH = 43;
    static constexpr int DEFAULT_KEY_LENGTH = 43;
    static constexpr int DEFAULT_E = 17;

public:

    RSA();

    ~RSA();

    static uint64_t encrypt(RSAKey key, uint64_t plain);

    static uint64_t decrypt(RSAKey key, uint64_t encrypted);

    static std::pair<RSAKey, RSAKey> generateKeys(int bitLength=DEFAULT_KEY_LENGTH, bool useDefaultE=false);

//private:

    static uint64_t modInverse(uint64_t a, uint64_t phi);

    static uint64_t gcd(uint64_t a, uint64_t b);

    static uint64_t generatePrime(int length);

    static bool isPrime(uint64_t number);

    static uint64_t generateNumber(uint64_t min, uint64_t max);

    static uint64_t pow_uint64(uint64_t base, uint64_t exp, uint64_t modulus=UINT64_MAX);

    static uint64_t mul_uint64(__uint128_t a, uint64_t b, uint64_t modulus=UINT64_MAX);

};


#endif //RSA_H
