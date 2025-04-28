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
    const auto start = std::chrono::high_resolution_clock::now();
    auto [publicKey, privateKey] = RSA::generateKeys();
    const auto end = std::chrono::high_resolution_clock::now();
    const auto dur_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    const auto dur_mins = std::chrono::duration_cast<std::chrono::minutes>(end - start);

    std::cout << "Keygen time in ms: " << dur_ms.count() << " ms or " << dur_mins.count() << " minutes." << std::endl;
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
