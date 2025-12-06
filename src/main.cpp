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

    std::ifstream input{argv[2], std::ios::binary};
    if (!input.good()) {
        std::print(stderr, "couldn't open input: {}\n", argv[2]);
        return 1;
    }

    b4ac::crypto_key key;
    if (!b4ac::parse_key(argv[3], key)) {
        std::print(stderr, "couldn't parse key: {}\n", argv[3]);
        return 1;
    }

    std::ofstream output{argv[4], std::ios::binary};
    if (!output.good()) {
        std::print(stderr, "couldn't open output: {}\n", argv[4]);
        return 1;
    }

    if (action == 'd') {
        b4ac::decrypt(output, input, key);
    } else {
        b4ac::encrypt(output, input, key);
    }

    return 0;
}

}  // namespace

int main(int argc, char* argv[]) {
    auto ret = main_impl(argc, argv);
    if (ret != 0) {
        std::print(stderr, "usage: {} <d|e> <input> <key> <output>\n", argv[0]);
    }
    return ret;
}

#endif
