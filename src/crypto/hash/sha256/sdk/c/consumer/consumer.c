#include <abc/abc.h>

#undef NDEBUG
#include <assert.h>
#include <string.h>

_Static_assert(sizeof(abc_status) == 4, "the ABI status is 32-bit");
_Static_assert(ABC_SHA256_DIGEST_BYTES == 32, "the ABI digest is 32 bytes");

int main(void) {
    static const uint8_t expected[ABC_SHA256_DIGEST_BYTES] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    static const uint8_t message[] = {'a', 'b', 'c'};
    uint8_t output[ABC_SHA256_DIGEST_BYTES] = {0};
    abc_sha256 *context = NULL;

    assert(abc_abi_version() == ABC_ABI_VERSION);
    assert(strcmp(abc_sha256_implementation(), "sha256-abc-rust-portable") == 0);
    assert(abc_sha256_digest(NULL, 1, output, sizeof output) == ABC_ERROR_NULL);
    assert(abc_sha256_digest(message, sizeof message, output, 1) == ABC_ERROR_LENGTH);
    assert(output[0] == 0);
    assert(abc_sha256_digest(message, sizeof message, output, sizeof output) == ABC_OK);
    assert(memcmp(output, expected, sizeof expected) == 0);

    assert(abc_sha256_new(NULL) == ABC_ERROR_NULL);
    assert(abc_sha256_new(&context) == ABC_OK);
    assert(abc_sha256_update(context, message, 1) == ABC_OK);
    assert(abc_sha256_update(context, NULL, 0) == ABC_OK);
    assert(abc_sha256_update(context, message + 1, 2) == ABC_OK);
    assert(abc_sha256_finalize(context, output, 0) == ABC_ERROR_LENGTH);
    assert(abc_sha256_finalize(context, output, sizeof output) == ABC_OK);
    assert(memcmp(output, expected, sizeof expected) == 0);
    assert(abc_sha256_update(context, NULL, 0) == ABC_ERROR_STATE);
    assert(abc_sha256_finalize(context, output, sizeof output) == ABC_ERROR_STATE);
    assert(abc_sha256_reset(context) == ABC_OK);
    assert(abc_sha256_update(context, message, sizeof message) == ABC_OK);
    assert(abc_sha256_finalize(context, output, sizeof output) == ABC_OK);
    assert(memcmp(output, expected, sizeof expected) == 0);
    abc_sha256_free(context);
    abc_sha256_free(NULL);
    return 0;
}
