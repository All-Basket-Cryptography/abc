#ifndef ABC_CRYPTO_SHA256_HPP
#define ABC_CRYPTO_SHA256_HPP

#include <abc/abc.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>

namespace abc {

inline const char *status_message(abc_status status) noexcept {
    switch (status) {
    case ABC_ERROR_NULL: return "null pointer";
    case ABC_ERROR_LENGTH: return "length or capacity outside the supported range";
    case ABC_ERROR_STATE: return "SHA-256 context is finalized or moved from";
    case ABC_ERROR_ALIGNMENT: return "misaligned pointer";
    case ABC_ERROR_ALLOC: return "SHA-256 context allocation failed";
    case ABC_ERROR_PANIC: return "SHA-256 provider panicked";
    default: return "unknown ABC error";
    }
}

class error final : public std::runtime_error {
public:
    explicit error(abc_status status) : std::runtime_error(status_message(status)), status_(status) {}
    abc_status status() const noexcept { return status_; }

private:
    abc_status status_;
};

inline void check(abc_status status) {
    if (status != ABC_OK) {
        throw error(status);
    }
}

using digest256 = std::array<std::uint8_t, ABC_SHA256_DIGEST_BYTES>;

inline digest256 sha256(const std::uint8_t *input, std::size_t size) {
    digest256 output{};
    check(abc_sha256_digest(input, size, output.data(), output.size()));
    return output;
}

class sha256_stream final {
public:
    sha256_stream() {
        abc_sha256 *raw = nullptr;
        check(abc_sha256_new(&raw));
        context_.reset(raw);
    }

    sha256_stream(const sha256_stream &) = delete;
    sha256_stream &operator=(const sha256_stream &) = delete;
    sha256_stream(sha256_stream &&) noexcept = default;
    sha256_stream &operator=(sha256_stream &&) noexcept = default;

    void update(const std::uint8_t *input, std::size_t size) {
        check(abc_sha256_update(context(), input, size));
    }

    digest256 finalize() {
        digest256 output{};
        check(abc_sha256_finalize(context(), output.data(), output.size()));
        return output;
    }

    void reset() { check(abc_sha256_reset(context())); }

private:
    struct deleter {
        void operator()(abc_sha256 *value) const noexcept { abc_sha256_free(value); }
    };

    abc_sha256 *context() const {
        if (!context_) {
            throw error(ABC_ERROR_STATE);
        }
        return context_.get();
    }

    std::unique_ptr<abc_sha256, deleter> context_;
};

} // namespace abc

#endif
