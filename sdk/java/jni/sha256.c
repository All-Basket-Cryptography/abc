#include "org_allbasket_abc_Sha256.h"
#include "abc/abc.h"

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm;
    (void)reserved;
    return abc_abi_version() == ABC_ABI_VERSION ? JNI_VERSION_1_8 : JNI_ERR;
}

JNIEXPORT jstring JNICALL Java_org_allbasket_abc_Sha256_implementation(JNIEnv *env, jclass cls) {
    (void)cls;
    return (*env)->NewStringUTF(env, abc_sha256_implementation());
}

JNIEXPORT jint JNICALL Java_org_allbasket_abc_Sha256_newContext(JNIEnv *env, jclass cls, jlongArray output) {
    (void)cls;
    abc_sha256 *context = NULL;
    jint result = abc_sha256_new(&context);
    if (result == 0) {
        jlong handle = (jlong)(uintptr_t)context;
        (*env)->SetLongArrayRegion(env, output, 0, 1, &handle);
        if ((*env)->ExceptionCheck(env)) abc_sha256_free(context);
    }
    return result;
}

JNIEXPORT jint JNICALL Java_org_allbasket_abc_Sha256_hash(JNIEnv *env, jclass cls, jbyteArray input, jbyteArray output) {
    (void)cls;
    jsize length = (*env)->GetArrayLength(env, input);
    jbyte *bytes = length == 0 ? NULL : (*env)->GetByteArrayElements(env, input, NULL);
    if (length != 0 && bytes == NULL) return 5;
    uint8_t digest[32];
    jint result = abc_sha256_digest((const uint8_t *)bytes, (size_t)length, digest, sizeof(digest));
    if (bytes != NULL) (*env)->ReleaseByteArrayElements(env, input, bytes, JNI_ABORT);
    if (result == 0) (*env)->SetByteArrayRegion(env, output, 0, sizeof(digest), (const jbyte *)digest);
    return result;
}

JNIEXPORT jint JNICALL Java_org_allbasket_abc_Sha256_append(JNIEnv *env, jclass cls, jlong handle, jbyteArray input) {
    (void)cls;
    jsize length = (*env)->GetArrayLength(env, input);
    jbyte *bytes = length == 0 ? NULL : (*env)->GetByteArrayElements(env, input, NULL);
    if (length != 0 && bytes == NULL) return 5;
    jint result = abc_sha256_update((abc_sha256 *)(uintptr_t)handle, (const uint8_t *)bytes, (size_t)length);
    if (bytes != NULL) (*env)->ReleaseByteArrayElements(env, input, bytes, JNI_ABORT);
    return result;
}

JNIEXPORT jint JNICALL Java_org_allbasket_abc_Sha256_finalizeDigest(JNIEnv *env, jclass cls, jlong handle, jbyteArray output) {
    (void)cls;
    uint8_t digest[32];
    jint result = abc_sha256_finalize((abc_sha256 *)(uintptr_t)handle, digest, sizeof(digest));
    if (result == 0) (*env)->SetByteArrayRegion(env, output, 0, sizeof(digest), (const jbyte *)digest);
    return result;
}

JNIEXPORT jint JNICALL Java_org_allbasket_abc_Sha256_resetContext(JNIEnv *env, jclass cls, jlong handle) {
    (void)env;
    (void)cls;
    return abc_sha256_reset((abc_sha256 *)(uintptr_t)handle);
}

JNIEXPORT jint JNICALL Java_org_allbasket_abc_Sha256_drop(JNIEnv *env, jclass cls, jlong handle) {
    (void)env;
    (void)cls;
    abc_sha256_free((abc_sha256 *)(uintptr_t)handle);
    return ABC_OK;
}
