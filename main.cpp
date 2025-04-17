//
// Created by bripl on 4/16/2025.
//

#include <format>
#include <numeric>

#include "RSA.h"

int main(int argc, char* argv[]) {

    auto [publicKey, privateKey] = RSA::generateKeys();
    // Message to be encrypted
    constexpr int message = 232123;
    std::cout << "Original message: " << message << std::endl;
    // Encrypted message
    const uint64_t hidden = RSA::encrypt(publicKey, message);
    std::cout << "Encryption: " << hidden << std::endl;
    // Decrypted message
    const uint64_t decrypted = RSA::decrypt(privateKey, hidden);
    std::cout << "Decryption: " << decrypted << std::endl;

    return 0;
}
