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

/**
 * Computes the gcd of two numbers a and b.
 * @param a The first number
 * @param b The second number
 * @return The gcd of a and b
 */
uint64_t RSA::gcd(const uint64_t a, const uint64_t b) {
    if (b == 0) {
        return a;
    }
    return gcd(b, a%b);
}

/**
 * Calculates the modular inverse from a and phi such that a*x + phi*y = 1 if a and m are coprime.
 * Uses the extended euclidian algorithm.
 * @param a The number who's inverse we calculate
 * @param m The modulus used in calculating the inverse
 * @return Returns the modular inverse
 */
uint64_t RSA::modInverse(uint64_t a, uint64_t m) {
    const uint64_t m0 = m;
    int64_t x0 = 0, x1 = 1;
    if (m == 1) {
        return 0;
    }
    while (a > 1) {
        uint64_t q = a / m;
        uint64_t t = m;
        m = a % m;
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

/**
 * Generates RSA keys given a desired length in bits. Will generate keys using a key using the
 * length's-1 significant bit. For example ig length is 4, n
 * @param bitLength
 * @param useDefaultE A bool flag to use the default value for e or generate a random e instead
 */
std::pair<RSAKey, RSAKey> RSA::generateKeys(const int bitLength, const bool useDefaultE) {
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

    const uint64_t n = static_cast<uint64_t>(p)*q;
    const uint64_t phi = (static_cast<uint64_t>(p)-1)*(q-1);
    std::cout << "p: " << p << " q: " << q << " n: " << n <<  " phi: "<< phi << std::endl;

    uint64_t e = DEFAULT_E;
    if (!useDefaultE) {
        do {
            e = generateNumber(2,phi-1);
        } while (gcd(e, phi) != 1);
    }

    std::cout << "e: " << e;
    const uint64_t d = modInverse(e, phi);
    std::cout << " d: " << d << std::endl;

    // Populate keys
    auto publicKey = RSAKey(e, n);
    auto privateKey = RSAKey(d, n);

    return std::make_pair(publicKey, privateKey);
}

/**
 * Generate a prime nuber of given length. Will generate random numbers until a prime is found.
 * @param length The bit length of the number to generate
 * @return A 64 bit long prime number
 */
uint64_t RSA::generatePrime(const int length) {
    const uint64_t min = pow_uint64(3, static_cast<uint64_t>(length-1));
    const uint64_t max = pow_uint64(3, static_cast<uint64_t>(length))-1;
    for (;;) {
        if (const uint64_t potential = generateNumber(min, max); isPrime(potential)) return potential;
    }
}

/**
 * Check that a given number is prime by checking that n mod X == 0 for all odd numbers x in [5, sqrt(n)].
 * @param number The number whose primality is being tested
 * @return Boolean indicating if the number is prime
 */
bool RSA::isPrime(const uint64_t number) {
    if (number >1 && number < 4) return true;
    const auto sqrtP = static_cast<uint64_t>(std::sqrt(number));
    if (number % 2 == 0) return false;
    for (uint64_t i = 3; i <= sqrtP; i+=2) {
        if (number % i == 0) return false;
    }
    return true;
}

/**
 * Generates a random number within a range of two given integers.
 * @param min The minimum of values to be generated
 * @param max The maximum of values to be generated
 * @return A random unsigned integer
 */
uint64_t RSA::generateNumber(const uint64_t min, const uint64_t max) {
    std::random_device rd;
    std::mt19937 rng(rd());
    std::uniform_int_distribution distribution(min, max);
    return distribution(rng);
}


/**
 * Performs modular multiplication on unsigned 64-bit integers if a modulus is given.
 * Prevents overflow while allowing use of all bits.
 * @param a The first number to multiply
 * @param b The second number to multiply
 * @param mod The modulus
 * @return The product of a and b modulus mod if mod is given
 */
uint64_t RSA::mul_uint64(__uint128_t a, uint64_t b, const uint64_t mod) {
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

/**
 * Perform modular exponentiation by a given modulus using unsigned 64-bit integer
 * @param base The base number
 * @param exp The exponent
 * @param modulus The number to modulus by
 * @return The resulting unsigned 64 integer of base to the power of exp.
 */
uint64_t RSA::pow_uint64(uint64_t base, uint64_t exp, const uint64_t modulus) {
    __uint128_t res = 1;
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
