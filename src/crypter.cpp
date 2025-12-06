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

}  // namespace

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

void decrypt(std::ostream& output, std::istream& input, const crypto_key& key) {
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

    while (true) {
        const constexpr auto chunk_size = 0x1000;

        uint8_t ciphertext[chunk_size];
        input.read(reinterpret_cast<char*>(&ciphertext[0]), sizeof(ciphertext));
        auto ciphertext_size = (ULONG)input.gcount();

        uint8_t plaintext[chunk_size];
        ULONG plaintext_size{};
        if ((status = BCryptDecrypt(key_handle, &ciphertext[0], ciphertext_size, nullptr, nullptr,
                                    0, &plaintext[0], sizeof(plaintext), &plaintext_size, 0))
            != 0) {
            throw std::runtime_error("couldn't decrypt chunk");
        }

        // Remove padding
        if (ciphertext_size != chunk_size || input.eof()) {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
            plaintext_size -= plaintext[plaintext_size - 1];
        }

        output.write(reinterpret_cast<char*>(&plaintext[0]), plaintext_size);

        if (ciphertext_size != chunk_size || input.eof()) {
            break;
        }
    }
}

void encrypt(std::ostream& output, std::istream& input, const crypto_key& key) {
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

    while (true) {
        const constexpr auto encryption_block_size = 0x10;  // can't change
        const constexpr auto chunk_size = 0x1000;           // tunable

        uint8_t plaintext[chunk_size];
        input.read(reinterpret_cast<char*>(&plaintext[0]), sizeof(plaintext));
        auto plaintext_size = (ULONG)input.gcount();

        if (plaintext_size != chunk_size) {
            auto num_padding = encryption_block_size - (plaintext_size % encryption_block_size);

            // This memset is safe since our chunks are a multiple of the block size
            // If plaintext_size == chunk_size - 1,  we'll only write one byte
            // We cannot fall in here in the case where it perfectly fills
            // NOLINTNEXTLINE(readability-magic-numbers)
            static_assert(chunk_size % 0x10 == 0);
            // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
            memset(&plaintext[plaintext_size], (int)num_padding, num_padding);
            plaintext_size += num_padding;
        }

        uint8_t ciphertext[chunk_size];
        ULONG ciphertext_size{};
        if ((status = BCryptEncrypt(key_handle, &plaintext[0], plaintext_size, nullptr, nullptr, 0,
                                    &ciphertext[0], sizeof(ciphertext), &ciphertext_size, 0))
            != 0) {
            throw std::runtime_error("couldn't encrypt chunk");
        }

        output.write(reinterpret_cast<char*>(&ciphertext[0]), ciphertext_size);

        if (plaintext_size == chunk_size && input.eof()) {
            // Edge case: If the plaintext perfectly fills our buffer, the padding falls into the
            // next block. Just handle it now, before we exit.
            memset(&plaintext[0], encryption_block_size, encryption_block_size);
            plaintext_size = encryption_block_size;
            if ((status = BCryptEncrypt(key_handle, &plaintext[0], plaintext_size, nullptr, nullptr,
                                        0, &ciphertext[0], sizeof(ciphertext), &ciphertext_size, 0))
                != 0) {
                throw std::runtime_error("couldn't encrypt chunk");
            }
            output.write(reinterpret_cast<char*>(&ciphertext[0]), ciphertext_size);
        }

        if (plaintext_size != chunk_size || input.eof()) {
            break;
        }
    }
}

}  // namespace b4ac
