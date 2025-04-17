//
// Created by bripl on 4/8/2025.
//

#include "RSA.h"

#include <complex>
#include <memory>
#include <random>


uint64_t RSA::encrypt(const RSAKey key, const uint64_t plain) {
   return pow_uint64(plain, key.exponent, key.n);
}

uint64_t RSA::decrypt(const RSAKey key, const uint64_t encrypted) {
    return pow_uint64(encrypted, key.exponent, key.n);
}

uint64_t RSA::gcd(const uint64_t a, const uint64_t b) {
    if (b == 0) {
        return a;
    }
    return gcd(b, a%b);
}


uint64_t RSA::modInverse(uint64_t a, uint64_t phi) {
    const uint64_t m0 = phi;
    int64_t x0 = 0, x1 = 1;
    if (phi == 1) {
        return 0;
    }
    while (a > 1) {
        uint64_t q = a / phi;
        uint64_t t = phi;
        phi = a % phi;
        a = t;
        t = x0;
        x0 = x1- static_cast<int64_t>(q)*x0;
        x1 = t;
    }
    if (a != 1) {
        std::cerr << "No inverse" << std::endl;
        return 0;
    }
    uint64_t inv = x1;
    if (x1 < 0) inv = x1+m0;
    return inv;
}


std::pair<RSAKey, RSAKey> RSA::generateKeys(const uint64_t bitLength, const bool useDefaultE) {
    if (bitLength > MAX_KEY_LENGTH) {
        std::cerr << "Maximum key bit length is " << MAX_KEY_LENGTH << std::endl;
        return std::make_pair(RSAKey(), RSAKey());
    }
    // Generate two primes p and q, as well as n and phi(n).
    const uint64_t p = generatePrime(bitLength/2);
    uint64_t q = 0;
    do {
        q = generatePrime(bitLength/2);
    } while (q == p);

    const uint64_t n = p*q;
    const uint64_t phi = (p-1)*(q-1);
    std::cout << "p: " << p << " q: " << q << std:: endl;
    std::cout << "n: " << n <<  " phi: "<< phi << std::endl;

    uint64_t e = DEFAULT_E;
    if (!useDefaultE) {
        do {
            e = generateNumber(2,phi-1);
        } while (gcd(e, phi) != 1);
    }

    const uint64_t d = modInverse(e, phi);
    std::cout << "Public key: " << e << ", " << n << std::endl;
    std::cout << "Private Key: " << d << ", " << n << std::endl;

    // Populate keys
    auto publicKey = RSAKey(e, n);
    auto privateKey = RSAKey(d, n);

    return std::make_pair(publicKey, privateKey);
}

uint64_t RSA::generatePrime(const uint64_t length) {
    const uint64_t min = pow_uint64(2,length-1);
    const uint64_t max = pow_uint64(2, length)-1;

    for (;;) {
        if (const uint64_t potential = generateNumber(min, max); isPrime(potential)) return potential;
    }
}


bool RSA::isPrime(const uint64_t number) {
    if (number >1 && number < 4) return true;
    const auto sqrtP = static_cast<uint64_t>(std::sqrt(number));
    if (number % 2 == 0) return false;
    for (uint64_t i = 3; i <= sqrtP; i+=2) {
        if (number % i == 0) return false;
    }
    return true;
}

uint64_t RSA::generateNumber(const uint64_t min, const uint64_t max) {
    std::random_device rd;
    std::mt19937 rng(rd());
    std::uniform_int_distribution distribution(min, max);
    return distribution(rng);
}

uint64_t RSA::mul_uint64(__uint128_t a, uint64_t b, const uint64_t mod) {
    if (b > UINT64_MAX || a > UINT64_MAX){
        std::cerr << "RSA::mul_uint64: a or b are too big. Max size: " << UINT64_MAX << std::endl;
        return 0;
    }
    __uint128_t result = 0;
    a %= mod;
    b %= mod;

    while (b > 0) {
        if (b & 1) {
            if (result >= mod - a) {
                result = result + a - mod;
            } else {
                result = result + a;
            }
        }
        b >>= 1;
        if (a >= mod - a) {
            a = a + a - mod;
        } else {
            a = a + a;
        }

    }

    return result;
}

uint64_t RSA::pow_uint64(uint64_t base, uint64_t exp, const uint64_t modulus) {
    uint64_t res = 1;
    base %= modulus;
    while (exp > 0) {
        if (exp & 1) res = mul_uint64(res, base, modulus);
        base = mul_uint64(base, base, modulus);
        exp >>= 1;
    }
    return res;
}

RSA::RSA()= default;

RSA::~RSA() = default;
