#include "PasswordGenerator.hpp"

#include <gtest/gtest.h>

#include <cctype>
#include <set>

using PasswordGenerator::Options;

TEST(PasswordGeneratorTest, ProducesRequestedLength) {
    Options options;
    options.length = 32;
    EXPECT_EQ(PasswordGenerator::generate(options).size(), 32u);
}

TEST(PasswordGeneratorTest, RejectsZeroLength) {
    Options options;
    options.length = 0;
    EXPECT_THROW(PasswordGenerator::generate(options), std::invalid_argument);
}

TEST(PasswordGeneratorTest, RejectsNegativeLength) {
    Options options;
    options.length = -5;
    EXPECT_THROW(PasswordGenerator::generate(options), std::invalid_argument);
}

TEST(PasswordGeneratorTest, RejectsAllCharacterClassesDisabled) {
    Options options;
    options.includeUppercase = false;
    options.includeLowercase = false;
    options.includeDigits = false;
    options.includeSymbols = false;
    EXPECT_THROW(PasswordGenerator::generate(options), std::invalid_argument);
}

TEST(PasswordGeneratorTest, DigitsOnlyProducesOnlyDigits) {
    Options options;
    options.includeUppercase = false;
    options.includeLowercase = false;
    options.includeSymbols = false;
    options.includeDigits = true;
    options.length = 50;

    const std::string password = PasswordGenerator::generate(options);
    for (unsigned char c : password) {
        EXPECT_TRUE(std::isdigit(c)) << "Non-digit character found: " << c;
    }
}

TEST(PasswordGeneratorTest, UppercaseOnlyProducesOnlyUppercase) {
    Options options;
    options.includeLowercase = false;
    options.includeDigits = false;
    options.includeSymbols = false;
    options.includeUppercase = true;
    options.length = 50;

    const std::string password = PasswordGenerator::generate(options);
    for (unsigned char c : password) {
        EXPECT_TRUE(std::isupper(c)) << "Non-uppercase character found: " << c;
    }
}

// Probabilistic, not exact: drawing one character 500 times from a
// 10-symbol pool (digits) should produce noticeably more than one or
// two distinct values. A true source of randomness could theoretically
// fail this by chance, but the odds are astronomically small - this is
// really checking "did we accidentally return the same thing every
// time," which would indicate a broken random source, not bad luck.
TEST(PasswordGeneratorTest, ProducesVariedOutputAcrossCalls) {
    Options options;
    options.includeUppercase = false;
    options.includeLowercase = false;
    options.includeSymbols = false;
    options.includeDigits = true;
    options.length = 1;

    std::set<char> seen;
    for (int i = 0; i < 500; ++i) {
        seen.insert(PasswordGenerator::generate(options)[0]);
    }
    EXPECT_GE(seen.size(), 5u);
}

TEST(PasswordGeneratorTest, TwoGenerationsProduceDifferentPasswords) {
    Options options;
    options.length = 20;
    const std::string first = PasswordGenerator::generate(options);
    const std::string second = PasswordGenerator::generate(options);
    EXPECT_NE(first, second);
}
