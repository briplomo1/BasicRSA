//
// Created by bripl on 4/16/2025.
//

#include <format>
#include <numeric>

#include "RSA.h"

int main(int argc, char* argv[]) {
    auto [publicKey, privateKey] = RSA::generateKeys();
    constexpr int message = 23;
    std::cout << "Original message: " << message << std::endl;
    const uint64_t hidden = RSA::encrypt(publicKey, message);
    std::cout << "Encryption: " << hidden << std::endl;
    const uint64_t message2 = RSA::decrypt(privateKey, hidden);
    std::cout << "Decryption: " << message2 << std::endl;

    // uint64_t msg = 3;
    // uint64_t e = 8196397979168421109ULL;
    // uint64_t d = 1356100879434505401ULL;
    // uint64_t n = 11128731280374866325ULL;
    // uint64_t phi = 11128731269330639756ULL;
    // uint64_t g = std::gcd(e, phi);
    // std::cout << (n-e) << ", " << n-d << std::endl;
    // std::cout << "gcd: " << g << std::endl;
    // std::cout << "test: " << e/1024 << std::endl;
    // std::cout << "test2: " << phi/1024 << std::endl;
    // uint64_t t = 10867901630205702*1024;
    // std::cout << "test3: " << 8004294901531661*1024 << ", " << t << std::endl;
    //
    // uint64_t cipher = RSA::pow_uint64(msg, e, n);
    // std::cout << "Encrypted: " << cipher << std::endl;
    //
    // uint64_t plain = RSA::pow_uint64(cipher, d, n);
    // std::cout << "Decrypted: " << plain << std::endl;
    return 0;
}
