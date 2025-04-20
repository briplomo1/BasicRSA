//
// Created by bripl on 4/16/2025.
//

#include <cassert>
#include <format>
#include <numeric>

#include "RSA.h"
#include "BigInt.h"

using namespace RSAEncryption;

int main(int argc, char* argv[]) {
    auto [publicKey, privateKey] = RSA::generateKeys();
    // Message to be encrypted
    constexpr int message = 21;
    std::cout << "Original message: " << message << std::endl;
    // Encrypted message
    const BigInt hidden = RSA::encrypt(publicKey, message);
    std::cout << "Encryption: " << hidden << std::endl;
    // Decrypted message
    const BigInt decrypted = RSA::decrypt(privateKey, hidden);
    std::cout << "Decryption: " << decrypted << std::endl;
    return 0;
}
