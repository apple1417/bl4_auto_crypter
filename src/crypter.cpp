#include "pch.h"
#include "crypter.h"

namespace b4ac {

namespace {

const constexpr crypto_key BASE_KEY = {
    0x35, 0xec, 0x33, 0x77, 0xf3, 0x5d, 0xb0, 0xea, 0xbe, 0x6b, 0x83, 0x11, 0x54, 0x03, 0xeb, 0xfb,
    0x27, 0x25, 0x64, 0x2e, 0xd5, 0x49, 0x06, 0x29, 0x05, 0x78, 0xbd, 0x60, 0xba, 0x4a, 0xa7, 0x87,
};

template <typename F>
struct RaiiLambda {
    F func;

    [[nodiscard]] RaiiLambda(F&& func) : func(std::move(func)) {}
    ~RaiiLambda() { func(); }

    RaiiLambda(const RaiiLambda&) = delete;
    RaiiLambda& operator=(const RaiiLambda&) = delete;
    RaiiLambda(RaiiLambda&&) = delete;
    RaiiLambda& operator=(RaiiLambda&&) = delete;
};

/**
 * @brief Encrypts or decrypts the given data.
 *
 * @param input The input to encrypt/decrypt.
 * @param input_size The size of the input.
 * @param key The crypto key to use.
 * @param crypto_func One of BCryptEncrypt or BCryptDecrypt
 * @return A vector of the output data.
 */
std::vector<uint8_t> encrypt_decrypt(uint8_t* input,
                                     size_t input_size,
                                     const crypto_key& key,
                                     decltype(BCryptEncrypt) crypto_func) {
    NTSTATUS status{};
    BCRYPT_ALG_HANDLE aes_alg_handle = nullptr;
    if ((status = BCryptOpenAlgorithmProvider(&aes_alg_handle, BCRYPT_AES_ALGORITHM, nullptr, 0))
        != 0) {
        throw std::runtime_error("couldn't get aes provider");
    }
    const RaiiLambda raii1{[&]() { BCryptCloseAlgorithmProvider(aes_alg_handle, 0); }};

    wchar_t mode[] = BCRYPT_CHAIN_MODE_ECB;
    if ((status =
             BCryptSetProperty(aes_alg_handle, BCRYPT_CHAINING_MODE, reinterpret_cast<PUCHAR>(mode),
                               sizeof(BCRYPT_CHAIN_MODE_ECB), 0))
        != 0) {
        throw std::runtime_error("couldn't set chaining mode");
    }

    struct {
        BCRYPT_KEY_DATA_BLOB_HEADER header{};
        crypto_key key{};
    } key_blob = {
        .header =
            {
                .dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC,
                .dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1,
                .cbKeyData = (ULONG)key.size(),
            },
        .key = key,
    };

    BCRYPT_KEY_HANDLE key_handle = nullptr;
    if ((status =
             BCryptImportKey(aes_alg_handle, nullptr, BCRYPT_KEY_DATA_BLOB, &key_handle, nullptr, 0,
                             reinterpret_cast<PUCHAR>(&key_blob), sizeof(key_blob), 0))
        != 0) {
        throw std::runtime_error("couldn't import key");
    }
    const RaiiLambda raii2{[&]() { BCryptDestroyKey(key_handle); }};

    // With this alg, intput and output are always the same size (assuming padded input)
    std::vector<uint8_t> output(input_size);
    ULONG output_size{};
    if ((status = crypto_func(key_handle, input, (ULONG)input_size, nullptr, nullptr, 0,
                              output.data(), (ULONG)output.size(), &output_size, 0))
        != 0) {
        throw std::runtime_error("en/decrypt failed");
    }
    if (output_size != output.size()) {
        throw std::runtime_error("encryption buffer was wrong");
    }
    output.resize(output_size);

    return output;
}

}  // namespace

bool parse_key(std::string_view account_id, crypto_key& out_key) {
    std::ranges::copy(BASE_KEY, out_key.begin());

    // Since we ultimately get input from a file path, we can be a bit stricter on the format
    // e.g. no need to strip whitespace
    // Epic account id: 32 hex characters
    // Steam account id: 64-bit (decimal) int, typically 17 digits

    constexpr auto epic_account_id_len = 32;

    // Anything longer must be invalid
    static_assert(epic_account_id_len > std::numeric_limits<uint64_t>::max_digits10);
    if (account_id.size() > epic_account_id_len) {
        return false;
    }

    if (account_id.size() == epic_account_id_len) {
        // Assume an epic account id
        // We're apparently suppose to encode as utf16-le - but we can assume all chars are ascii

        // Since these are the same size to begin with, but utf16 doubles it, the second half just
        // falls off the end
        static_assert(epic_account_id_len == sizeof(out_key));
        for (size_t i = 0; i < (epic_account_id_len / 2); i++) {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
            out_key[(2 * i) + 0] ^= account_id[i];
            // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
            out_key[(2 * i) + 1] ^= 0x00;
        }
        return true;
    }

    // Otherwise, assume must be a steam account id
    uint64_t steam_uid{};
    if (std::from_chars(account_id.data(), account_id.data() + account_id.size(), steam_uid).ec
        == std::errc{}) {
        // https://developer.valvesoftware.com/wiki/SteamID
        // While the docs say universe 0 is common, in practice everyone says 17 digit ids
        // NOLINTNEXTLINE(readability-magic-numbers)
        if (steam_uid > 0x0100'0000'0000'0000) {
            // NOLINTNEXTLINE(readability-magic-numbers)
            std::array<uint8_t, 8> bytes{};
            static_assert(std::endian::native == std::endian::little);
            memcpy(bytes.data(), &steam_uid, sizeof(steam_uid));

            for (size_t i = 0; i < bytes.size(); i++) {
                // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
                out_key[i] ^= bytes[i];
            }
            return true;
        }
    }

    return false;
}

void decrypt(const std::filesystem::path& yaml,
             const std::filesystem::path& sav,
             const crypto_key& key) {
    std::vector<uint8_t> file_contents(std::filesystem::file_size(sav));
    std::ifstream{sav, std::ios::binary}.read(reinterpret_cast<char*>(file_contents.data()),
                                              (std::streamsize)file_contents.size());

    std::vector<uint8_t> decrypted =
        encrypt_decrypt(file_contents.data(), file_contents.size(), key, BCryptDecrypt);

    auto compressed_size = decrypted.size();

    // Strip padding
    compressed_size -= decrypted.back();

    // Grab the decompressed size out
    uint32_t decompressed_size{};
    compressed_size -= sizeof(decompressed_size);
    memcpy(&decompressed_size, file_contents.data() + compressed_size, sizeof(decompressed_size));

    std::vector<uint8_t> output(decompressed_size);
    auto dest_len = (uLongf)decompressed_size;
    if (::uncompress(output.data(), &dest_len, decrypted.data(), (uLong)compressed_size) != Z_OK) {
        throw std::runtime_error("decompression failled");
    }

    std::ofstream{yaml, std::ios::binary}.write(reinterpret_cast<char*>(output.data()),
                                                (std::streamsize)dest_len);
}

void encrypt(const std::filesystem::path& sav,
             const std::filesystem::path& yaml,
             const crypto_key& key) {
    std::vector<uint8_t> file_contents(std::filesystem::file_size(yaml));
    std::ifstream{yaml, std::ios::binary}.read(reinterpret_cast<char*>(file_contents.data()),
                                               (std::streamsize)file_contents.size());

    std::vector<uint8_t> compressed(compressBound((uLong)file_contents.size()));
    auto compressed_size = (uLongf)compressed.size();
    if (::compress2(compressed.data(), &compressed_size, file_contents.data(),
                    (uLong)file_contents.size(), Z_DEFAULT_COMPRESSION)
        != Z_OK) {
        throw std::runtime_error("compression failed");
    }

    auto decompressed_size = (uint32_t)file_contents.size();

    // In case we perfectly filled the buffer, need to resize to add the worst case on top of that
    // In 99% of cases we'll have plenty of free space so this shouldn't need an extra allocation
    constexpr auto encryption_block_size = 16;
    constexpr auto worst_case_added_bytes = sizeof(decompressed_size) + encryption_block_size;
    compressed.resize(compressed_size + worst_case_added_bytes);

    // Add the decompressed size and padding onto the end
    memcpy(compressed.data() + compressed_size, &decompressed_size, sizeof(decompressed_size));
    compressed_size += sizeof(decompressed_size);

    uint8_t num_padding = encryption_block_size - (compressed_size % encryption_block_size);
    memset(compressed.data() + compressed_size, num_padding, num_padding);
    compressed_size += num_padding;

    auto output = encrypt_decrypt(compressed.data(), compressed_size, key, BCryptEncrypt);
    std::ofstream{sav, std::ios::binary}.write(reinterpret_cast<char*>(output.data()),
                                               (std::streamsize)output.size());
}

}  // namespace b4ac
