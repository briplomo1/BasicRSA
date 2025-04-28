//
// Created by bripl on 4/8/2025.
//

#include "RSA.h"

#include <complex>
#include <memory>
#include <random>
#include <stop_token>
#include <thread>

namespace RSAEncryption {

    std::mutex mtx;

    BigInt RSA::encrypt(const RSAKey& key, const BigInt& plain) {
        return BigInt::pow(plain, key.exponent, key.n);
    }

    BigInt RSA::decrypt(const RSAKey& key, const BigInt& encrypted) {
        return BigInt::pow(encrypted, key.exponent, key.n);
    }

    BigInt RSA::gcd(const BigInt& a, const BigInt& b) {

        if (b == 0) {
            return a;
        }
        //std::cout << "gcd"  << a << ", " << b << std::endl;
        return gcd(b, a%b);
    }


    BigInt RSA::modInverse(BigInt a, BigInt mod) {
        //std::cout << "modInverse" << std::endl;
        if (mod.isZero()) throw std::invalid_argument("Modulo cannot be zero");

        BigInt m0 = mod, t = 0, newt = 1;
        BigInt r = mod, newr = a % mod;

        while (!newr.isZero()) {
            BigInt quotient = r / newr;
            BigInt temp = newt;
            newt = t - (quotient * newt);
            t = temp;
            temp = newr;
            newr = r - (quotient * newr);
            r = temp;
        }
        if (r != 1) {
            throw std::invalid_argument("Modular inverse does not exist");
        }

        if (t < 0) {
            t += m0;
        }

        return t;
    }


    std::pair<RSAKey, RSAKey> RSA::generateKeys(const size_t bitLength, const bool useDefaultE) {
        if (bitLength > DEFAULT_KEY_LENGTH) {
            std::cerr << "Maximum key bit length is " << DEFAULT_KEY_LENGTH << std::endl;
            return std::make_pair(RSAKey(), RSAKey());
        }
        const unsigned THREAD_COUNT = std::thread::hardware_concurrency();
        std::cout << "Generating keys using " <<  THREAD_COUNT << " threads" << std::endl;
        // Setup multithreading flag and threads
        std::atomic<bool> exitFlag(false);
        std::atomic<int> tryCount(0);
        // Create threads
        std::vector<std::thread> findPrimeThreads;
        findPrimeThreads.reserve(THREAD_COUNT);

        // Generate two primes p and q, as well as n and phi(n).
        std::cout << "Generating prime p..." << std::endl;
        std::shared_ptr<BigInt> p = std::make_shared<BigInt>(0);
        for (int i = 0; i < THREAD_COUNT; i++) {
            findPrimeThreads.emplace_back(generatePrime, bitLength/2, p, std::ref(exitFlag), std::ref(tryCount));
        }
        for (int i= 0; i < THREAD_COUNT; i++) {
            findPrimeThreads[i].join();
        }
        findPrimeThreads.clear();
        // Reset flag for next prime gen
        exitFlag.store(false);
        tryCount.store(0);
        std::cout << "P: " << *p << std::endl;

        std::cout << "Generating prime q..." << std::endl;
        std::shared_ptr<BigInt> q = std::make_shared<BigInt>(0);
        for (int i = 0; i < THREAD_COUNT; i++) {
            findPrimeThreads.emplace_back(generatePrime, bitLength/2, q, std::ref(exitFlag),std::ref(tryCount));
        }
        for (int i= 0; i < THREAD_COUNT; i++) {
            findPrimeThreads[i].join();
        }
        // do {
        //
        // } while (*q == *p);

        std::cout << "Q: " << *q << std::endl;


        const BigInt n = *p * *q;
        const BigInt phi = (*p-1)*(*q-1);
        std::cout << "N: " << n <<  "\nPhi: "<< phi << std::endl;
        std::cout << "Generating e..." << std::endl;
        BigInt e = DEFAULT_E;
        if (!useDefaultE) {
            do {

                e = BigInt::random(5,phi-1);
                //std::cout << "Gen e" << std::endl;
            } while (gcd(e, phi) != 1);
        }
        std::cout << "E: " << e << std::endl;
        std::cout << "Generating d..." << std::endl;
        const BigInt d = modInverse(e, phi);
        std::cout << "D: " << d << std::endl;
        std::cout << "Public key:\n" << e << ", " << n << std::endl;
        std::cout << "Private Key:\n" << d << ", " << n << std::endl;

        // Populate keys
        auto publicKey = RSAKey(e, n);
        auto privateKey = RSAKey(d, n);

        return std::make_pair(publicKey, privateKey);
    }

    void RSA::generatePrime(const size_t length, const std::shared_ptr<BigInt>& prime, std::atomic<bool>& exitFlag, std::atomic<int>& tryCount) {
        //std::cout << "Gen prime..." << std::endl;
        try {
            while (!exitFlag.load()) {
                if (const BigInt potential = BigInt::random(length); isPrime(potential)){
                    std::cout << "Prime found. Tries: " << tryCount << std::endl;
                    mtx.lock();
                    *prime = potential;
                    mtx.unlock();
                    exitFlag.store(true);
                }
                tryCount.store(++tryCount);
            }
        } catch (const std::exception& e) {
            std::cout <<" Error in thread: " << e.what() << std::endl;
        }
    }


    bool RSA::isPrime(const BigInt& number) {
        // Amount of miller-rabin rounds
        int k=5;
        if (number == 2 || number == 3) return true;
        if (number <= 1 || number % 2 == 0) return false;
        BigInt d = number - 1;
        int s = 0;
        while (d % 2 == 0) {
            d >>= 1;
            s++;
        }

        for (int i = 0; i < k; i++) {
            BigInt a = BigInt::random(2, number - 2);
            BigInt x = BigInt::pow(a, d, number);
            if (x == 1 || x == number - 1) continue;

            bool is_composite = true;
            for (int r = 0; r < s - 1; r++) {
                x = BigInt::pow(x, 2, number);
                if (x == number - 1) {
                    is_composite = false;
                    break;
                }
            }
            if (is_composite) return false;
        }
        return true;
    }


    RSA::RSA()= default;

    RSA::~RSA() = default;

}
