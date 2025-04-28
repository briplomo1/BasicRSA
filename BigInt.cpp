//
// Created by bripl on 4/17/2025.
//

#include "BigInt.h"

#include <algorithm>
#include <iostream>
#include <random>
#include <sstream>

namespace RSAEncryption {
    // Constructors //////////////////////////////////////////////////

    BigInt::BigInt() : is_negative(false) {
        std::lock_guard lock(mutex);
        //std::cout << "Construct1" << std::endl;
        data.push_back(0);
    }

    BigInt::BigInt(int value):  BigInt(static_cast<int64_t>(value)) {}

    BigInt::BigInt(int64_t value) : is_negative(value < 0) {
        std::lock_guard lock(mutex);
        //std::cout << "Construct 3" << std::endl;
        uint64_t nValue = std::abs(value); // Work with absolute value for simplicity

        // Convert the value to binary digits and store in 'data'
        while (nValue > 0) {
            data.push_back(nValue & 0xFFFFFFFF); // Store 32 bits at a time
            nValue >>= 32; // Right shift to get the next 32 bits
        }

        if (data.empty()) {
            data.push_back(0); // Ensure there's at least one 32-bit chunk (for 0)
        }
    }

    BigInt::BigInt(uint64_t value) : is_negative(false) {
        std::lock_guard lock(mutex);
        //std::cout << "Construct 4" << std::endl;
        while (value > 0) {
            data.push_back(value & 0xFFFFFFFF);
            value >>= 32;
        }
        if (data.empty()) {
            data.push_back(0); // Ensure there's at least one 32-bit chunk (for 0)
        }
    }

    // Copy constructor
    BigInt::BigInt(const BigInt& other) {
        //std::cout << "Copy" << std::endl;
        //std::lock_guard lock(other.mutex);
        is_negative = other.is_negative;
        data = other.data;
    }
    // Copy initialization
    BigInt& BigInt::operator=(const BigInt& other) {
        //std::lock(this->mutex, other.mutex);
        is_negative = other.is_negative;
        data = other.data;
        //mutex.unlock();
        //other.mutex.unlock();
        return *this;
    }
    // Move constructor
    BigInt::BigInt(BigInt&& other)  noexcept {
        //std::lock_guard lock(other.mutex);
        data = std::move(other.data);
        other.data.clear();
        is_negative = other.is_negative;
    }
    // Move initialization
    BigInt& BigInt::operator=(BigInt&& other)  noexcept {
        //std::unique_lock lock(mutex), other_lock(other.mutex);
        //std::lock(lock, other_lock);
        data = std::move(other.data);
        other.data.clear();
        is_negative = other.is_negative;
        return *this;
    }

    //////////////////////////////////////////////////////////////

    BigInt::operator bool() const {
        return !isZero();  // Return true if the number is non-zero, false if it's zero
    }

    // Method to check if BigInt is zero
    bool BigInt::isZero() const {
        // Assuming the `data` vector represents the digits of the BigInt
        return data.size() == 1 && data[0] == 0;
    }

    BigInt::BigInt(const std::string& str) {
        BigInt result;
        is_negative = !str.empty() && str[0] == '-';
        size_t i = is_negative ? 1 : 0;
        for (; i < str.size(); ++i) {
            result *= 10;
            result += (str[i] - '0');
        }
        *this = result;
        if (isZero()) is_negative = false;
    }

    void BigInt::trim() {
        while (data.size() > 1 && data.back() == 0) {
            data.pop_back();
        }

        if (data.empty()) {
            data.push_back(0);  // Ensure at least one digit (for zero)
        }
    }

    int BigInt::compareAbs(const BigInt& a, const BigInt& b) {
        if (a.data.size() < b.data.size()) {
            return -1;  // a is smaller
        }
        if (a.data.size() > b.data.size()) {
            return 1;   // a is larger
        }

        // If they have the same size, compare each chunk (from the most significant to least significant)
        for (size_t i = a.data.size(); i-- > 0;) {
            if (a.data[i] < b.data[i]) {
                return -1;  // a is smaller
            } else if (a.data[i] > b.data[i]) {
                return 1;   // a is larger
            }
        }

        return 0;
    }

    BigInt BigInt::addAbs(const BigInt& a, const BigInt& b) {
        BigInt result;
        size_t max_size = std::max(a.data.size(), b.data.size());
        result.data.resize(max_size);

        uint64_t carry = 0;
        for (size_t i = 0; i < max_size; ++i) {
            uint64_t ai = (i < a.data.size()) ? a.data[i] : 0;
            uint64_t bi = (i < b.data.size()) ? b.data[i] : 0;

            uint64_t sum = ai + bi + carry;
            result.data[i] = static_cast<uint32_t>(sum);
            carry = sum >> 32;  // Carry over
        }

        if (carry) {
            result.data.push_back(static_cast<uint32_t>(carry));
        }

        result.trim();
        return result;
    }

    BigInt BigInt::subAbs(const BigInt& a, const BigInt& b) {
        BigInt result;
        result.data.resize(a.data.size());

        uint64_t borrow = 0;
        for (size_t i = 0; i < a.data.size(); ++i) {
            uint64_t ai = a.data[i];
            uint64_t bi = (i < b.data.size()) ? b.data[i] : 0;

            if (ai < bi + borrow) {
                result.data[i] = static_cast<uint32_t>(ai + (1ULL << 32) - bi - borrow);
                borrow = 1;
            } else {
                result.data[i] = static_cast<uint32_t>(ai - bi - borrow);
                borrow = 0;
            }
        }

        result.trim();
        return result;
    }

    // Arithmetic operators
    BigInt BigInt::operator+(const BigInt& other) const {
        if (is_negative == other.is_negative) {
            BigInt result = addAbs(*this, other);
            result.is_negative = is_negative;
            return result;
        }
        if (compareAbs(*this, other) >= 0) {
            BigInt result = subAbs(*this, other);
            result.is_negative = is_negative;
            return result;
        }
        BigInt result = subAbs(other, *this);
        result.is_negative = other.is_negative;
        return result;
    }

    BigInt BigInt::operator-(const BigInt& other) const {
        if (is_negative != other.is_negative) {
            // a - (-b) = a + b
            // (-a) - b = -(a + b)
            BigInt result = addAbs(*this, other);
            result.is_negative = is_negative;
            return result;
        }

        if (compareAbs(*this, other) >= 0) {
            // |a| >= |b|
            BigInt result = subAbs(*this, other);
            result.is_negative = is_negative; // sign follows *this
            return result;
        }
        // |a| < |b| => result is negative of |b - a|
        BigInt result = subAbs(other, *this);
        result.is_negative = !is_negative; // sign is flipped
        return result;
    }

    BigInt BigInt::operator*(const BigInt& other) const {
        BigInt result;
        result.data.resize(this->data.size() + other.data.size(), 0);

        for (size_t i = 0; i < this->data.size(); ++i) {
            uint64_t carry = 0;
            for (size_t j = 0; j < other.data.size(); ++j) {
                uint64_t temp = static_cast<uint64_t>(this->data[i]) * other.data[j] + result.data[i + j] + carry;
                result.data[i + j] = static_cast<uint32_t>(temp & 0xFFFFFFFF);
                carry = temp >> 32;
            }
            result.data[i + other.data.size()] += static_cast<uint32_t>(carry);
        }

        result.is_negative = this->is_negative != other.is_negative;
        result.trim(); // Remove leading zeros
        return result;
    }

    BigInt BigInt::operator/(const BigInt& other) const {
        //std::cout << "/" << std::endl;
        if (other.isZero()) {
            throw std::invalid_argument("Division by zero");
        }

        BigInt dividend = *this;
        BigInt divisor = other;
        dividend.is_negative = false;
        divisor.is_negative = false;

        if (compareAbs(dividend, divisor) < 0) {
            return BigInt(0);
        }

        BigInt quotient;
        BigInt remainder;

        int totalBits = static_cast<int>(dividend.data.size() * 32);
        quotient.data = std::vector<uint32_t>((totalBits + 31) / 32, 0);

        for (int i = totalBits - 1; i >= 0; --i) {
            // Shift remainder left by 1
            remainder <<= 1;

            // Bring in the current bit from dividend
            size_t word = i / 32;
            size_t bit = i % 32;
            if ((dividend.data[word] >> bit) & 1) {
                if (remainder.data.empty()) remainder.data.push_back(0);
                remainder.data[0] |= 1;
            }

            // If remainder >= divisor, subtract and set bit in quotient
            if (compareAbs(remainder, divisor) >= 0) {
                remainder -= divisor;

                size_t qword = i / 32;
                size_t qbit = i % 32;
                quotient.data[qword] |= (1U << qbit);
            }
        }

        quotient.trim();
        quotient.is_negative = is_negative != other.is_negative && !quotient.isZero();
        //std::cout << "/ done" << std::endl;
        return quotient;
    }

    BigInt BigInt::operator%(const BigInt& other) const {
        //std::cout << "mod" << std::endl;
        if (other.isZero()) {
            throw std::invalid_argument("Modulo by zero");
        }

        BigInt dividend = *this;
        BigInt divisor = other;

        // Work with absolute values
        dividend.is_negative = false;
        divisor.is_negative = false;

        if (compareAbs(dividend, divisor) < 0) {
            return *this;
        }

        BigInt remainder = dividend;
        BigInt shifted_divisor = divisor;
        BigInt one(1);

        // Shift the divisor left until it's just smaller than or equal to dividend
        std::vector<BigInt> powers;
        while (compareAbs(shifted_divisor, remainder) <= 0) {
            powers.push_back(shifted_divisor);
            shifted_divisor <<= 1;
        }

        // Subtract the largest possible shifted divisor repeatedly
        for (int i = static_cast<int>(powers.size()) - 1; i >= 0; --i) {
            if (compareAbs(powers[i], remainder) <= 0) {
                remainder -= powers[i];
            }
        }

        remainder.is_negative = this->is_negative;
        remainder.trim();
        return remainder;


    }

    // Math with integer other operand
    // BigInt BigInt::operator-(const int& other) const {
    //     return *this - BigInt(other);  // Use the BigInt operator to handle the subtraction
    // }
    //
    // BigInt& BigInt::operator-=(const int& other) {
    //     return *this -= BigInt(other);  // Use the BigInt operator to handle the subtraction
    // }
    //
    // BigInt BigInt::operator+(const int& other) const {
    //     return *this + BigInt(other);  // Add using the BigInt operator
    // }
    //
    // BigInt& BigInt::operator+=(const int& other) {
    //     return *this += BigInt(other);  // Add using the BigInt operator
    // }
    //
    // BigInt BigInt::operator*(const int& other) const {
    //     return *this * BigInt(other);  // Multiply using the BigInt operator
    // }
    //
    // BigInt& BigInt::operator*=(const int& other) {
    //     return *this *= BigInt(other);  // Multiply using the BigInt operator
    // }
    //
    // BigInt BigInt::operator/(const int& other) const {
    //     return *this / BigInt(other);  // Divide using the BigInt operator
    // }
    //
    // BigInt& BigInt::operator/=(const int& other) {
    //     return *this /= BigInt(other);  // Divide using the BigInt operator
    // }
    //
    // BigInt BigInt::operator%(const int& other) const {
    //     return *this % BigInt(other);  // Modulo using the BigInt operator
    // }
    //
    // BigInt& BigInt::operator%=(const int& other) {
    //     return *this %= BigInt(other);  // Modulo using the BigInt operator
    // }

    // Arithmetic assignment operators
    BigInt& BigInt::operator+=(const BigInt& other) {
        *this = *this + other;
        return *this;
    }

    BigInt& BigInt::operator-=(const BigInt& other) {
        *this = *this - other;
        return *this;
    }

    BigInt& BigInt::operator*=(const BigInt& other) {
        *this = *this * other;
        return *this;
    }

    BigInt& BigInt::operator/=(const BigInt& other) {
        *this = *this / other;
        return *this;
    }

    BigInt& BigInt::operator%=(const BigInt& other) {
        *this = *this % other;
        return *this;
    }


    BigInt BigInt::sqrt() const {
        if (is_negative) {
            throw std::invalid_argument("Square root is not defined for negative numbers");
        }

        BigInt low(0);
        BigInt high = *this;
        BigInt mid;
        BigInt one(1);

        while (low <= high) {
            mid = low + (high - low) / 2;

            BigInt midSquared = mid * mid;

            // Check if we found the exact square root
            if (midSquared == *this) {
                return mid;
            }
            // If mid^2 is less than the number, move the lower bound
            else if (midSquared < *this) {
                low = mid + one;
            }
            // If mid^2 is greater than the number, move the upper bound
            else {
                high = mid - one;
            }
        }

        return high; // This will return the integer part of the square root
    }

    BigInt BigInt::random(const size_t bit_length) {

        if (bit_length == 0) return {0};

        BigInt result;
        result.data.resize((bit_length + 31) / 32, 0); // Each uint32_t holds 32 bits
        result.is_negative = false;

        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint32_t> dist(0, UINT32_MAX);

        for (unsigned int & i : result.data) {
            i = dist(gen);
        }

        // Mask bits above the requested bit length to ensure exact size
        if (const size_t extra_bits = (32 * result.data.size()) - bit_length; extra_bits > 0) {
            result.data.back() &= ((1ULL << (32 - extra_bits)) - 1);
        }

        // Use all bits
        if (bit_length > 0) {
            const size_t top_index = (bit_length - 1) / 32;
            const size_t top_bit = (bit_length - 1) % 32;
            result.data[top_index] |= (1U << top_bit);
        }

        result.trim();
        //std::cout << "Rand: " << result << std::endl;
        return result;
    }

    BigInt BigInt::random(const BigInt& min, const BigInt& max) {
        BigInt range = max - min;
        std::random_device rd;
        std::mt19937_64 gen(rd());  // 64-bit random number generator
        std::uniform_int_distribution<uint64_t> dis(0, std::numeric_limits<uint64_t>::max());
        //std::cout << "Range: " << range << std::endl;
        BigInt range_val = dis(gen);  // Generate a random number

        // Adjust the random number to fit in the range
        range_val = range_val % range;  // Adjust within the range
        BigInt random_value = min + range_val;  // Add the minimum value to adjust

        return random_value;
    }

    BigInt BigInt::pow(BigInt base, BigInt exponent, const BigInt& modulus) {
        //std::cout  << "powMod " << "base: " << base << " exp: " << exponent << " mod: " << modulus << std::endl;
        if (exponent.is_negative) {
             throw std::invalid_argument("Negative exponent not supported");
        }
        if (modulus.isZero()) {
            throw std::invalid_argument("Modulo must be non-zero in powMod");
        }
        BigInt result(1);

        base %= modulus;

        while (!exponent.isZero()) {
            if ((exponent.data[0] & 1) != 0) {
                //std::cout << "Res: " << result << " Base: " << base;
                result = (result*base) % modulus;
                //std::cout << " new      Res: " << result << std::endl;
            }
            base = (base * base) % modulus;
            exponent >>= 1;
            //std::cout << "exp: " << exponent << " newBase: " << base << std::endl;
        }
        //std::cout << "powMod done" << std::endl;
        return result;
    }

    BigInt BigInt::pow(BigInt base, BigInt exponent) {
        //std::cout << "pow no mod" << std::endl;
        if (exponent.is_negative) {
            throw std::invalid_argument("Negative exponent not supported");
        }

        BigInt result(1);

        while (!exponent.isZero()) {
            if ((exponent.data[0] & 1) != 0) {
                result *= base;
            }
            base *= base;
            exponent >>= 1;
            //std::cout << "res: " << result << " Base: " << base << std::endl;

        }
        //std::cout << "pow no mod done\n\n " << std::endl;
        return result;
    }

    // Comparison operators
    bool BigInt::operator==(const BigInt& other) const {
        return is_negative == other.is_negative && data == other.data;
    }

    bool BigInt::operator!=(const BigInt& other) const {
        return !(*this == other);
    }

    bool BigInt::operator<(const BigInt& other) const {
        if (is_negative != other.is_negative) return is_negative;
        int cmp = compareAbs(*this, other);
        return is_negative ? cmp > 0 : cmp < 0;
    }

    bool BigInt::operator<=(const BigInt& other) const {
        return *this < other || *this == other;
    }

    bool BigInt::operator>(const BigInt& other) const {
        return !(*this <= other);
    }

    bool BigInt::operator>=(const BigInt& other) const {
        return !(*this < other);
    }

    // Bitwise operators
    BigInt BigInt::operator&(const BigInt& other) const {
        BigInt result;
        size_t n = std::min(data.size(), other.data.size());
        result.data.resize(n);
        for (size_t i = 0; i < n; ++i)
            result.data[i] = data[i] & other.data[i];
        result.trim();
        return result;
    }

    BigInt BigInt::operator|(const BigInt& other) const {
        BigInt result;
        size_t n = std::max(data.size(), other.data.size());
        result.data.resize(n);
        for (size_t i = 0; i < n; ++i) {
            uint32_t a = i < data.size() ? data[i] : 0;
            uint32_t b = i < other.data.size() ? other.data[i] : 0;
            result.data[i] = a | b;
        }
        result.trim();
        return result;
    }

    BigInt BigInt::operator^(const BigInt& other) const {
        BigInt result;
        size_t n = std::max(data.size(), other.data.size());
        result.data.resize(n);
        for (size_t i = 0; i < n; ++i) {
            uint32_t a = i < data.size() ? data[i] : 0;
            uint32_t b = i < other.data.size() ? other.data[i] : 0;
            result.data[i] = a ^ b;
        }
        result.trim();
        return result;
    }

    BigInt BigInt::operator~() const {
        BigInt result = *this;
        for (auto& word : result.data)
            word = ~word;
        result.trim();
        return result;
    }

    BigInt& BigInt::operator&=(const BigInt& other) {
        *this = *this & other;
        return *this;
    }

    BigInt& BigInt::operator|=(const BigInt& other) {
        *this = *this | other;
        return *this;
    }

    BigInt& BigInt::operator^=(const BigInt& other) {
        *this = *this ^ other;
        return *this;
    }

    // Shift operators
    BigInt BigInt::operator<<(const size_t shift) const {
        BigInt result = *this;
        result <<= shift;
        return result;
    }

    BigInt& BigInt::operator<<=(const size_t shift) {
        shiftLeft(shift);
        return *this;
    }

    BigInt BigInt::operator>>(const size_t shift) const {
        BigInt result = *this;
        result >>= shift;
        return result;
    }

    BigInt& BigInt::operator>>=(const size_t shift) {
        shiftRight(shift);
        return *this;
    }

    // Shift helpers
    void BigInt::shiftLeft(const size_t bits) {
        size_t chunk_shift = bits / 32;
        size_t bit_shift = bits % 32;

        if (bit_shift != 0) {
            uint64_t carry = 0;
            for (unsigned int & i : data) {
                uint64_t val = (static_cast<uint64_t>(i) << bit_shift) | carry;
                i = static_cast<uint32_t>(val);
                carry = val >> 32;
            }
            if (carry) {
                data.push_back(static_cast<uint32_t>(carry));
            }
        }

        for (size_t i = 0; i < chunk_shift; ++i) {
            data.push_back(0);
        }
    }

    void BigInt::shiftRight(const size_t bits) {
        size_t chunk_shift = bits / 32;
        size_t bit_shift = bits % 32;

        if (chunk_shift > 0) {
            data.erase(data.begin(), data.begin() + chunk_shift);
        }

        if (bit_shift > 0) {
            uint64_t carry = 0;
            for (size_t i = data.size(); i-- > 0;) {
                uint64_t val = static_cast<uint64_t>(data[i]);
                data[i] = static_cast<uint32_t>((val >> bit_shift) | carry);
                carry = static_cast<uint32_t>(val << (32 - bit_shift));
            }
        }

        trim();
    }

    std::string BigInt::toString() const {
        //std::cout << "To string." << std::endl;
        //std::cout << this->data[0] << std::endl;
        if (isZero()) return "0";

        BigInt value = *this;
        value.is_negative = false;

        std::string result;
        const BigInt ten(10);

        while (!value.isZero()) {
            BigInt remainder = value % ten;
            value /= ten;
            result += static_cast<char>('0' + remainder.data[0]);
        }



        if (is_negative) {
            result += '-';
        }

        std::ranges::reverse(result);
        //std::cout << "toString done" << std::endl;
        return result;
    }

}
