#include "pch.h"
#include "crypter.h"

namespace b4ac {

namespace {

const constexpr crypto_key BASE_KEY = {
    0x35, 0xec, 0x33, 0x77, 0xf3, 0x5d, 0xb0, 0xea, 0xbe, 0x6b, 0x83, 0x11, 0x54, 0x03, 0xeb, 0xfb,
    0x27, 0x25, 0x64, 0x2e, 0xd5, 0x49, 0x06, 0x29, 0x05, 0x78, 0xbd, 0x60, 0xba, 0x4a, 0xa7, 0x87,
};

}

bool parse_key(const std::string& account_id, crypto_key& out_key) {
    std::ranges::copy(BASE_KEY, out_key.begin());

    // TODO: epic

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

std::vector<uint8_t> decrypt(const std::filesystem::path& path, const crypto_key& key) {
    std::vector<uint8_t> ciphertext(std::filesystem::file_size(path));
    {
        std::ifstream stream{path, std::ios::binary};
        stream.read(reinterpret_cast<char*>(ciphertext.data()), (std::streamsize)ciphertext.size());
    }

    NTSTATUS status{};
    // TODO: proper error handling
    // TODO: free things
    // TODO: streaming?

    BCRYPT_ALG_HANDLE aes_alg_handle = nullptr;
    if ((status = BCryptOpenAlgorithmProvider(&aes_alg_handle, BCRYPT_AES_ALGORITHM, nullptr, 0))
        != 0) {
        throw std::runtime_error("couldn't get aes provider");
    }

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
                .cbKeyData = key.size(),
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

    ULONG plaintext_size{};
    if ((status = BCryptDecrypt(key_handle, ciphertext.data(), ciphertext.size(), nullptr, nullptr,
                                0, nullptr, 0, &plaintext_size, 0))
        != 0) {
        throw std::runtime_error("couldn't get plaintext size");
    }

    std::vector<uint8_t> plaintext(plaintext_size);
    if ((status = BCryptDecrypt(key_handle, ciphertext.data(), ciphertext.size(), nullptr, nullptr,
                                0, plaintext.data(), plaintext.size(), &plaintext_size, 0))
        != 0) {
        throw std::runtime_error("couldn't decrypt");
    }

    return plaintext;
}

}  // namespace b4ac
