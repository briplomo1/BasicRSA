//
// Created by bripl on 4/17/2025.
//

#ifndef BIGINT_H
#define BIGINT_H
#include <cstdint>
#include <mutex>
#include <ostream>
#include <vector>

namespace RSAEncryption {

    class BigInt {
    protected:
        mutable std::mutex mutex;
        std::vector<uint32_t> data; // binary digits, little-endian
        bool is_negative;
    public:
        // Constructors
        BigInt();
        BigInt(int value);
        BigInt(int64_t value);
        BigInt(uint64_t value);
        BigInt(const std::string& str);
        // Copy constructor
        BigInt(const BigInt& other);
        // Copy initialization
        BigInt& operator=(const BigInt& other);
        // Move constructor
        BigInt(BigInt&& other) noexcept ;
        // Move initialization
        BigInt& operator=(BigInt&& other) noexcept ;

        // Arithmetic
        BigInt operator+(const BigInt& other) const;
        BigInt operator-(const BigInt& other) const;
        BigInt operator*(const BigInt& other) const;
        BigInt operator/(const BigInt& other) const;
        BigInt operator%(const BigInt& other) const;

        BigInt& operator+=(const BigInt& other);
        BigInt& operator-=(const BigInt& other);
        BigInt& operator*=(const BigInt& other);
        BigInt& operator/=(const BigInt& other);
        BigInt& operator%=(const BigInt& other);


        // // Arithmetic with integer types
        BigInt operator+(const int64_t value) const { return *this + BigInt(value); }
        BigInt operator-(const int64_t value) const { return *this - BigInt(value); }
        BigInt operator*(const int64_t value) const { return *this * BigInt(value); }
        BigInt operator/(const int64_t value) const { return *this / BigInt(value); }
        BigInt operator%(const int64_t value) const { return *this % BigInt(value); }

        BigInt& operator+=(const int64_t value) { return *this += BigInt(value); }
        BigInt& operator-=(const int64_t value) { return *this -= BigInt(value); }
        BigInt& operator*=(const int64_t value) { return *this *= BigInt(value); }
        BigInt& operator/=(const int64_t value) { return *this /= BigInt(value); }
        BigInt& operator%=(const int64_t value) { return *this %= BigInt(value); }

        // Bitwise
        BigInt operator&(const BigInt& other) const;
        BigInt operator|(const BigInt& other) const;
        BigInt operator^(const BigInt& other) const;
        BigInt operator~() const;

        BigInt& operator&=(const BigInt& other);
        BigInt& operator|=(const BigInt& other);
        BigInt& operator^=(const BigInt& other);

        // Bitwise with integer types
        BigInt operator&(const int64_t value) const { return *this & BigInt(value); }
        BigInt operator|(const int64_t value) const { return *this | BigInt(value); }
        BigInt operator^(const int64_t value) const { return *this ^ BigInt(value); }

        BigInt& operator&=(const int64_t value) { return *this &= BigInt(value); }
        BigInt& operator|=(const int64_t value) { return *this |= BigInt(value); }
        BigInt& operator^=(const int64_t value) { return *this ^= BigInt(value); }

        // Shift
        BigInt operator<<(size_t shift) const;
        BigInt operator>>(size_t shift) const;

        BigInt& operator<<=(size_t shift);
        BigInt& operator>>=(size_t shift);

        // Comparison
        bool operator==(const BigInt& other) const;
        bool operator!=(const BigInt& other) const;
        bool operator<(const BigInt& other) const;
        bool operator<=(const BigInt& other) const;
        bool operator>(const BigInt& other) const;
        bool operator>=(const BigInt& other) const;

        explicit operator bool() const;
        static BigInt random(size_t bit_length);
        static BigInt random(const BigInt& min, const BigInt& max);
        [[nodiscard]] BigInt sqrt() const;
        static BigInt pow(BigInt base, BigInt exponent, const BigInt& modulus);
        static BigInt pow(BigInt base, BigInt exponent);

        // Comparison with integer types
        bool operator==(const int64_t value) const { return *this == BigInt(value); }
        bool operator!=(const int64_t value) const { return *this != BigInt(value); }
        bool operator<(const int64_t value) const { return *this < BigInt(value); }
        bool operator<=(const int64_t value) const { return *this <= BigInt(value); }
        bool operator>(const int64_t value) const { return *this > BigInt(value); }
        bool operator>=(const int64_t value) const { return *this >= BigInt(value); }

        // Utilities
        [[nodiscard]] bool isZero() const;
        [[nodiscard]] std::string toString() const;

        // Output stream
        friend std::ostream& operator<<(std::ostream& os, const BigInt& num) {
            os << num.toString();
            return os;
        }

    private:
        void trim();
        static int compareAbs(const BigInt& a, const BigInt& b);
        static BigInt addAbs(const BigInt& a, const BigInt& b);
        static BigInt subAbs(const BigInt& a, const BigInt& b);

        void shiftLeft(size_t bits);
        void shiftRight(size_t bits);

    };

}

#endif //BIGINT_H
