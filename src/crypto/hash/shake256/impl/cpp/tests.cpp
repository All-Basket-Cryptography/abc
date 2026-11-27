#include "shake256.hpp"
#include "../../../keccak-p1600/impl/cpp/test_support.hpp"

#include <algorithm>

using namespace abc::native_shake256;
using namespace abc::keccak_tests;

namespace {

Bytes read_all(Reader reader, std::size_t length) {
    Bytes output(length);
    require(reader.read(output.data(), length) == Status::ok, "one-shot reader");
    return output;
}

void split_message(const Case& item, std::size_t split, bool snapshot) {
    Hasher hasher;
    require(hasher.update(item.input.data(), split) == Status::ok, "prefix absorb");
    if (snapshot) {
        require(read_all(hasher.finalize(), item.prefix.size()) == item.prefix, "prefix snapshot");
    }
    require(hasher.update(nullptr, 0) == Status::ok, "empty absorb");
    require(hasher.update(suffix(item.input, split), item.input.size() - split) == Status::ok, "suffix absorb");
    auto reader = hasher.finalize();
    Bytes output(item.expected.size() + 3, 0xa5);
    const std::array<std::size_t, 7> requested{1, 7, 127, 1, 136, 137, 4096};
    std::size_t used = 0;
    for (const auto chunk : requested) {
        const auto size = std::min(chunk, item.expected.size() - used);
        require(reader.read(nullptr, 0) == Status::ok, "empty squeeze");
        require(reader.read(output.data() + used, size) == Status::ok, "split squeeze");
        used += size;
    }
    require(used == item.expected.size(), "fixture output exceeds split schedule");
    require(std::equal(item.expected.begin(), item.expected.end(), output.begin()), "split squeeze output");
    require(std::all_of(output.begin() + used, output.end(), [](auto b) { return b == 0xa5; }), "suffix canary");
    require(read_all(hasher.finalize(), item.expected.size()) == item.expected, "independent reader");
}

void checks() {
    Counts counts;
    Case item;
    while (next(item)) {
        Bytes output(item.expected.size());
        require(xof(item.input.data(), item.input.size(), output.data(), output.size()) == Status::ok, "one-shot XOF status");
        require(output == item.expected, "one-shot XOF output");
        counts.record(item);
        split_message(item, item.input.size() / 2, true);
        ++counts.snapshots;
        if (item.input.size() <= 273 && item.expected.size() <= 512) {
            for (std::size_t split = 0; split <= item.input.size(); ++split) {
                split_message(item, split, false);
                ++counts.splits;
            }
        }
    }
    Hasher hasher;
    const std::array<std::uint8_t, 3> message{'a', 'b', 'c'};
    auto caller = message;
    require(hasher.update(caller.data(), caller.size()) == Status::ok, "caller storage update");
    caller.fill(0);
    require(hasher.update(nullptr, 1) == Status::invalid_argument, "null input rejection");
    auto reader = hasher.finalize();
    require(reader.read(nullptr, 1) == Status::invalid_argument, "null output rejection");
    Bytes expected(409);
    require(xof(message.data(), message.size(), expected.data(), expected.size()) == Status::ok, "alias reference");
    require(read_all(reader, expected.size()) == expected, "rejected read or absorb changed state");
    hasher.reset();
    require(read_all(hasher.finalize(), 64) == read_all(Hasher{}.finalize(), 64), "reset did not clear stream");

    Bytes overlap(expected.size());
    std::copy(message.begin(), message.end(), overlap.begin());
    require(xof(overlap.data(), message.size(), overlap.data(), overlap.size()) == Status::ok && overlap == expected,
            "one-shot overlap");
    const auto before = overlap;
    require(xof(nullptr, 1, overlap.data(), overlap.size()) == Status::invalid_argument && overlap == before,
            "invalid input changed destination");
    require(xof(nullptr, 0, nullptr, 0) == Status::ok, "zero output");
    counts.print();
}

}  // namespace

int main(int argc, char** argv) {
    try {
        if (argc == 2 && std::string(argv[1]) == "--benchmark") {
            Bytes output(4096);
            benchmark([&output](const Bytes& input) {
                require(xof(input.data(), input.size(), output.data(), output.size()) == Status::ok, "benchmark XOF");
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
