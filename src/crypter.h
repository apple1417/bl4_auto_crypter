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
 * @param path Path to file to decrypt.
 * @param key The key to decrypt with.
 * @return The decrypted bytes.
 */
std::vector<uint8_t> decrypt(std::filesystem::path& path, const crypto_key& key);

/**
 * @brief Encrypts the given file.
 *
 * @param path Path to file to encrypt.
 * @param key The key to encrypt with.
 * @return The encrypted bytes.
 */
std::vector<uint8_t> encrypt(std::filesystem::path& path, const crypto_key& key);

}  // namespace b4ac
