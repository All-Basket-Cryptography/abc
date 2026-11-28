using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Provider = Org.BouncyCastle.Math.EC.Rfc8032.Ed25519;

namespace Abc.Cryptography;

/// Pure Ed25519 with strict point admission and the uncofactored OpenSSL equation.
public static class Ed25519
{
    private static readonly Lazy<NativeVerifier> Verifier = new(() => new NativeVerifier());

    public static byte[] PublicKey(ReadOnlySpan<byte> seed)
    {
        if (seed.Length != 32) throw new ArgumentException("Ed25519 requires a 32-byte seed", nameof(seed));
        var key = new byte[32];
        Provider.GeneratePublicKey(seed, key);
        return key;
    }

    public static byte[] Sign(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> message)
    {
        if (seed.Length != 32) throw new ArgumentException("Ed25519 requires a 32-byte seed", nameof(seed));
        var signature = new byte[64];
        Provider.Sign(seed, message, signature);
        return signature;
    }

    public static bool Verify(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        if (key.Length != 32 || signature.Length != 64) return false;
        var publicKey = key.ToArray();
        var encoding = signature.ToArray();
        if (!Provider.ValidatePublicKeyPartial(publicKey) || !Provider.ValidatePublicKeyPartial(encoding.AsSpan(0, 32)))
            return false;
        return Verifier.Value.Verify(publicKey, message.ToArray(), encoding);
    }

    private sealed class NativeVerifier
    {
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate uint Version();
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate nint Import(nint context, [MarshalAs(UnmanagedType.LPStr)] string algorithm,
            nint properties, byte[] key, nuint length);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate nint Allocate();
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void Release(nint pointer);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int Initialize(nint context, nint keyContext, nint digest, nint library,
            nint properties, nint key, nint parameters);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int Check(nint context, byte[] signature, nuint signatureLength, byte[] data, nuint length);

        private readonly Import import;
        private readonly Allocate allocate;
        private readonly Release releaseKey;
        private readonly Release releaseContext;
        private readonly Initialize initialize;
        private readonly Check check;

        internal NativeVerifier()
        {
            string? location = Environment.GetEnvironmentVariable("ABC_OPENSSL_LIBRARY");
            if (location is null || !Path.IsPathFullyQualified(location) || !File.Exists(location))
                throw new InvalidOperationException("Configure ABC_OPENSSL_LIBRARY with an absolute libcrypto path");
            nint handle = NativeLibrary.Load(location);
            try
            {
                if (Bind<Version>(handle, "OpenSSL_version_num")() < 0x30500000)
                    throw new InvalidOperationException("Ed25519 validation uses OpenSSL 3.5 or newer");
                import = Bind<Import>(handle, "EVP_PKEY_new_raw_public_key_ex");
                allocate = Bind<Allocate>(handle, "EVP_MD_CTX_new");
                releaseKey = Bind<Release>(handle, "EVP_PKEY_free");
                releaseContext = Bind<Release>(handle, "EVP_MD_CTX_free");
                initialize = Bind<Initialize>(handle, "EVP_DigestVerifyInit_ex");
                check = Bind<Check>(handle, "EVP_DigestVerify");
                // The immutable delegates and the library remain available for this process.
            }
            catch
            {
                NativeLibrary.Free(handle);
                throw;
            }
        }

        private static T Bind<T>(nint handle, string name) where T : Delegate =>
            Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(handle, name));

        internal bool Verify(byte[] publicKey, byte[] message, byte[] signature)
        {
            nint key = import(0, "ED25519", 0, publicKey, 32);
            if (key == 0) throw new CryptographicException("OpenSSL Ed25519 key import failed");
            try
            {
                nint context = allocate();
                if (context == 0) throw new CryptographicException("OpenSSL verification context allocation failed");
                try
                {
                    if (initialize(context, 0, 0, 0, 0, key, 0) != 1)
                        throw new CryptographicException("OpenSSL Ed25519 verification initialization failed");
                    int result = check(context, signature, 64, message, (nuint)message.Length);
                    return result == 1;
                }
                finally { releaseContext(context); }
            }
            finally { releaseKey(key); }
        }
    }
}
