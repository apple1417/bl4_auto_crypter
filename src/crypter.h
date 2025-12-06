#include "pch.h"

namespace b4ac {

using crypto_key = std::array<uint8_t, 32>;  // NOLINT(readability-magic-numbers)

/**
 * @brief Tries to parse a crypto key out of the given account id.
 *
 * @param account_id The account id to try parse.
 * @param out_key Reference to the key to write the output into.
 * @return True if parsing succeeded.
 */
[[nodiscard]] bool parse_key(const std::string& account_id, crypto_key& out_key);

/**
 * @brief Decrypts the given file.
 *
 * @param output Stream to write the decrypted file to.
 * @param input Stream to read encrypted input from.
 * @param key The key to decrypt with.
 */
void decrypt(std::ostream& output, std::istream& input, const crypto_key& key);

/**
 * @brief Encrypts the given file.
 *
 * @param output Stream to write the encrypted file to.
 * @param input Stream to read decrypted input from.
 * @param key The key to encrypt with.
 */
void encrypt(std::ostream& output, std::istream& input, const crypto_key& key);

}  // namespace b4ac
