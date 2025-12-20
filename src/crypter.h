#ifndef CRYPTER_H
#define CRYPTER_H

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
[[nodiscard]] bool parse_key(std::string_view account_id, crypto_key& out_key);

/**
 * @brief Decrypts the given file.
 *
 * @param yaml Path to output file to write decrypted yaml into.
 * @param sav Path to encrypted input sav file.
 * @param key The key to decrypt with.
 */
void decrypt(const std::filesystem::path& yaml,
             const std::filesystem::path& sav,
             const crypto_key& key);

/**
 * @brief Encrypts the given file.
 *
 * @param sav Path to output file to write encrypted sav into.
 * @param yaml Path to decrypted input yaml file.
 * @param key The key to encrypt with.
 */
void encrypt(const std::filesystem::path& sav,
             const std::filesystem::path& yaml,
             const crypto_key& key);

/**
 * @brief Gets the SHA1 hash of the given file.
 *
 * @param path Path to the file to hash.
 * @return The stringified SHA1.
 */
std::string sha1_file(const std::filesystem::path& path);

namespace internal {
// Just exposed for the exe

/**
 * @brief Encrypts/decrypts the given file, but does not (de)compress it.
 *
 * @param output Path to write output to.
 * @param intput Path to input file.
 * @param key The key to en/decrypt with.
 * @param crypto_func One of BCryptEncrypt or BCryptDecrypt
 */
void crypt_only(const std::filesystem::path& output,
                const std::filesystem::path& input,
                const crypto_key& key,
                decltype(BCryptEncrypt) crypto_func);

}  // namespace internal

}  // namespace b4ac

#endif /* CRYPTER_H */
