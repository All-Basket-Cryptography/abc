using System;
using System.IO;
using System.Text.Json;

internal static class TestSupport
{
    public static readonly byte[] RfcMessage = Convert.FromHexString(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a" +
        "204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f72207468" +
        "65206675747572652c2073756e73637265656e20776f756c642062652069742e");

    public static byte[] Hex(string text) => Convert.FromHexString(text);
    public static string Wire(ReadOnlySpan<byte> value) => Convert.ToHexStringLower(value);
    public static byte[] Field(JsonElement fixture, string field) => Hex(fixture.GetProperty(field).GetString()!);
    public static JsonDocument Parse(string path) => JsonDocument.Parse(File.ReadAllText(path));

    public static void Require(bool condition, string reason)
    {
        if (!condition) throw new InvalidOperationException(reason);
    }

    public static void Equal(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected, string reason)
    {
        if (!actual.SequenceEqual(expected))
            throw new InvalidOperationException($"{reason}. Got {Wire(actual)}, expected {Wire(expected)}.");
    }

    public static void Throws<T>(Action action) where T : Exception
    {
        try { action(); }
        catch (T) { return; }
        throw new InvalidOperationException($"Expected {typeof(T).Name}.");
    }
}
