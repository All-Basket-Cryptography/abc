#include "keccak_p1600.hpp"
#include "test_support.hpp"

using namespace abc::native_keccak_p1600;
using namespace abc::keccak_tests;

namespace {

State decode_lanes(const Bytes& bytes) {
    require(bytes.size() == 200, "invalid serialized state size");
    State lanes{};
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        lanes[i / 8] |= std::uint64_t{bytes[i]} << (8 * (i % 8));
    }
    return lanes;
}

}  // namespace

int main() {
    try {
        Counts counts;
        Case item;
        while (next(item)) {
            auto state = decode_lanes(item.input);
            permute(state);
            require(state == decode_lanes(item.expected), "permutation output");
            counts.record(item);
        }
        counts.print();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
