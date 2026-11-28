#include "sha3_256.hpp"
#include "../../../keccak-p1600/impl/cpp/test_support.hpp"

#include <algorithm>

using namespace abc::native_sha3_256;
using namespace abc::keccak_tests;

namespace {

bool matches(const Digest& actual, const Bytes& expected) {
    return std::equal(actual.begin(), actual.end(), expected.begin(), expected.end());
}

void split_message(const Case& item, std::size_t split, bool snapshot) {
    Hasher hasher;
    require(hasher.update(item.input.data(), split) == Status::ok, "prefix absorb");
    if (snapshot) require(matches(hasher.digest(), item.prefix), "prefix snapshot");
    require(hasher.update(nullptr, 0) == Status::ok, "empty absorb");
    require(hasher.update(suffix(item.input, split), item.input.size() - split) == Status::ok, "suffix absorb");
    require(matches(hasher.digest(), item.expected), "split digest");
    require(matches(hasher.digest(), item.expected), "repeated digest");
}

void checks() {
    Counts counts;
    Case item;
    while (next(item)) {
        Digest output{};
        require(hash(item.input.data(), item.input.size(), output) == Status::ok, "one-shot digest status");
        require(matches(output, item.expected), "one-shot digest output");
        counts.record(item);
        split_message(item, item.input.size() / 2, true);
        ++counts.snapshots;
        if (item.input.size() <= 273) {
            for (std::size_t split = 0; split <= item.input.size(); ++split) {
                split_message(item, split, false);
                ++counts.splits;
            }
        }
    }
    const std::array<std::uint8_t, 3> message{'a', 'b', 'c'};
    Digest expected{};
    require(hash(message.data(), message.size(), expected) == Status::ok, "overlap reference");
    Hasher stream;
    auto caller = message;
    require(stream.update(caller.data(), caller.size()) == Status::ok, "caller storage update");
    caller.fill(0);
    require(stream.update(nullptr, 1) == Status::invalid_argument, "null input rejection");
    require(stream.digest() == expected, "caller mutation or rejection changed stream");
    stream.reset();
    require(stream.digest() == Hasher{}.digest(), "reset did not clear stream");

    Digest overlap{};
    overlap.fill(0xa5);
    const auto before = overlap;
    require(hash(nullptr, 1, overlap) == Status::invalid_argument && overlap == before, "invalid output preservation");
    std::copy(message.begin(), message.end(), overlap.begin());
    require(hash(overlap.data(), message.size(), overlap) == Status::ok && overlap == expected, "one-shot overlap");
    counts.print();
}

}  // namespace

int main(int argc, char** argv) {
    try {
        if (argc == 2 && std::string(argv[1]) == "--benchmark") {
            Digest output{};
            benchmark([&output](const Bytes& input) {
                require(hash(input.data(), input.size(), output) == Status::ok, "benchmark hash");
            });
        } else {
            require(argc == 1, "unexpected test argument");
            checks();
        }
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
