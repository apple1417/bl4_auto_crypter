#include "pch.h"
#include "crypter.h"
#include "sync.h"

#ifdef CRYPTER_EXE

namespace {

int sync_impl(int argc, char* argv[], bool wait) {
    // NOLINTNEXTLINE(readability-magic-numbers)
    if (argc != 4) {
        std::print(stderr, "wrong num args\n");
        return 1;
    }

    b4ac::crypto_key key;
    if (!b4ac::parse_key(argv[2], key)) {
        std::print(stderr, "couldn't parse key: {}\n", argv[2]);
        return 1;
    }

    std::filesystem::path folder{argv[3]};
    if (!std::filesystem::exists(folder)) {
        std::print(stderr, "couldn't find folder: {}\n", argv[3]);
        return 1;
    }

    b4ac::sync_saves(folder, key);

    if (wait) {
        std::print(stdout, "first sync done; waiting for input\n");
        std::fflush(stdout);

        char dummy{};
        std::cin >> dummy;

        b4ac::sync_saves(folder, key);
    }

    return 0;
}

int crypt_impl(int argc, char* argv[], bool encrypt) {
    // NOLINTNEXTLINE(readability-magic-numbers)
    if (argc != 5) {
        std::print(stderr, "wrong num args\n");
        return 1;
    }

    b4ac::crypto_key key;
    if (!b4ac::parse_key(argv[2], key)) {
        std::print(stderr, "couldn't parse key: {}\n", argv[2]);
        return 1;
    }

    std::filesystem::path input{argv[3]};
    if (!std::filesystem::exists(input)) {
        std::print(stderr, "couldn't find input: {}\n", argv[3]);
        return 1;
    }

    std::filesystem::path output{argv[4]};
    // nothing to check?

    if (encrypt) {
        b4ac::encrypt(output, input, key);
    } else {
        b4ac::decrypt(output, input, key);
    }

    return 0;
}

int main_impl(int argc, char* argv[]) {
    if (argc < 2) {
        std::print(stderr, "wrong num args\n");
        return 1;
    }

    auto action = *argv[1];
    if (action == 'd') {
        return crypt_impl(argc, argv, false);
    }
    if (action == 'e') {
        return crypt_impl(argc, argv, true);
    }
    if (action == 's') {
        return sync_impl(argc, argv, false);
    }
    if (action == 'S') {
        return sync_impl(argc, argv, true);
    }

    std::print(stderr, "bad action: {}\n", action);
    return 1;
}

}  // namespace

int main(int argc, char* argv[]) {
    auto ret = main_impl(argc, argv);
    if (ret != 0) {
        std::print(stderr,
                   "usage: {} <d|e> <key> <input> <output>\n"
                   "       {} <s|S> <folder>\n",
                   argv[0], argv[0]);
    }
    return ret;
}

#endif
