using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.SafeDirectories)]

namespace Abc.Cryptography;

public static class Sha256
{
    public static string Implementation
    {
        get
        {
            Native.RequireCompatible();
            return Marshal.PtrToStringUTF8(Native.Implementation()) ?? throw new InvalidOperationException("Missing ABC provider identity");
        }
    }

    public static unsafe byte[] Digest(ReadOnlySpan<byte> input)
    {
        Native.RequireCompatible();
        byte[] output = new byte[32];
        fixed (byte* source = input)
        fixed (byte* destination = output)
        {
            Native.Check(Native.Digest(source, (nuint)input.Length, destination, (nuint)output.Length));
        }
        return output;
    }
}

public sealed class Sha256Stream : IDisposable
{
    private readonly object gate = new();
    private readonly ContextHandle context;

    public Sha256Stream()
    {
        Native.RequireCompatible();
        int status = Native.New(out context);
        if (status != 0 || context.IsInvalid)
        {
            context.Dispose();
            Native.Check(status);
            throw new InvalidOperationException("ABC returned an invalid context");
        }
    }

    public unsafe void Update(ReadOnlySpan<byte> input)
    {
        lock (gate)
        {
            RequireOpen();
            fixed (byte* source = input)
            {
                Native.Check(Native.Update(context, source, (nuint)input.Length));
            }
        }
    }

    public unsafe byte[] Finish()
    {
        lock (gate)
        {
            RequireOpen();
            byte[] output = new byte[32];
            fixed (byte* destination = output)
            {
                Native.Check(Native.Finish(context, destination, (nuint)output.Length));
            }
            return output;
        }
    }

    public void Reset()
    {
        lock (gate)
        {
            RequireOpen();
            Native.Check(Native.Reset(context));
        }
    }

    public void Dispose()
    {
        lock (gate) context.Dispose();
    }

    private void RequireOpen() => ObjectDisposedException.ThrowIf(context.IsClosed, this);
}

internal sealed class ContextHandle() : SafeHandleZeroOrMinusOneIsInvalid(true)
{
    protected override bool ReleaseHandle()
    {
        Native.Free(handle);
        return true;
    }
}

internal static unsafe class Native
{
    private const string Library = "abc_crypto";

    internal static void RequireCompatible()
    {
        if (!OperatingSystem.IsWindows() || RuntimeInformation.ProcessArchitecture != Architecture.X64)
            throw new PlatformNotSupportedException("This ABC research package supports Windows x64");
        if (Version() != 0x00010000) throw new InvalidOperationException("Incompatible ABC C ABI");
    }

    internal static void Check(int status)
    {
        switch (status)
        {
            case 0: return;
            case 1 or 2 or 4: throw new ArgumentException($"Invalid input or buffer for ABC SHA-256 ({status})");
            case 3: throw new InvalidOperationException("ABC SHA-256 operation already finished");
            case 5: throw new OutOfMemoryException("ABC SHA-256 allocation failed");
            default: throw new InvalidOperationException($"ABC SHA-256 native status {status}");
        }
    }

    [DllImport(Library, EntryPoint = "abc_abi_version", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint Version();

    [DllImport(Library, EntryPoint = "abc_sha256_implementation", CallingConvention = CallingConvention.Cdecl)]
    internal static extern nint Implementation();

    [DllImport(Library, EntryPoint = "abc_sha256_digest", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int Digest(byte* input, nuint length, byte* output, nuint capacity);

    [DllImport(Library, EntryPoint = "abc_sha256_new", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int New(out ContextHandle context);

    [DllImport(Library, EntryPoint = "abc_sha256_update", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int Update(ContextHandle context, byte* input, nuint length);

    [DllImport(Library, EntryPoint = "abc_sha256_finalize", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int Finish(ContextHandle context, byte* output, nuint capacity);

    [DllImport(Library, EntryPoint = "abc_sha256_reset", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int Reset(ContextHandle context);

    [DllImport(Library, EntryPoint = "abc_sha256_free", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void Free(nint context);
}
