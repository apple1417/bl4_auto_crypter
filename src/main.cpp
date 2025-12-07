#include "pch.h"
#include "crypter.h"

#ifdef CRYPTER_EXE

namespace {

int main_impl(int argc, char* argv[]) {
    // NOLINTNEXTLINE(readability-magic-numbers)
    if (argc != 5) {
        std::print(stderr, "wrong num args\n");
        return 1;
    }

    auto action = *argv[1];
    if (action != 'd' && action != 'e') {
        std::print(stderr, "bad action: {}\n", action);
        return 1;
    }

    b4ac::crypto_key key;
    if (!b4ac::parse_key(argv[2], key)) {
        std::print(stderr, "couldn't parse key: {}\n", argv[2]);
        return 1;
    }

    std::filesystem::path input{argv[3]};
    if (!std::filesystem::exists(input)) {
        std::print(stderr, "couldn't open input: {}\n", argv[3]);
        return 1;
    }

    std::ofstream output_file{argv[4], std::ios::binary};
    if (!output_file.good()) {
        std::print(stderr, "couldn't open output: {}\n", argv[4]);
        return 1;
    }

    auto output_bytes = action == 'd' ? b4ac::decrypt(input, key) : b4ac::encrypt(input, key);
    output_file.write(reinterpret_cast<char*>(output_bytes.data()),
                      (std::streamsize)output_bytes.size());

    return 0;
}

}  // namespace

int main(int argc, char* argv[]) {
    auto ret = main_impl(argc, argv);
    if (ret != 0) {
        std::print(stderr, "usage: {} <d|e> <key> <input> <output>\n", argv[0]);
    }
    return ret;
}

#endif
