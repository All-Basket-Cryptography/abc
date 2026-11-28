using System;
using System.Globalization;
using Abc.Cryptography;

static void Reject(Action action)
{
    try
    {
        action();
    }
    catch (ArgumentException)
    {
        return;
    }
    throw new InvalidOperationException("Invalid scrypt input accepted");
}

static long Workspace(int cost, int blockSize, int parallel)
    => 128L * blockSize * (cost + (long)parallel + 2) + 128;

Reject(() => Scrypt.WorkspaceSize(1, 1, 1));
Reject(() => Scrypt.WorkspaceSize(3, 1, 1));
Reject(() => Scrypt.WorkspaceSize(65536, 1, 1));
Reject(() => Scrypt.WorkspaceSize(16, 0, 1));
Reject(() => Scrypt.WorkspaceSize(16, 8, 0));
Reject(() => Scrypt.WorkspaceSize(16, 8, int.MaxValue));
Reject(() => Scrypt.WorkspaceSize(1 << 30, int.MaxValue, int.MaxValue));
Reject(() => Scrypt.WorkspaceSize(2, 4_000_000, 1));
byte[] empty = [];
Reject(() => Scrypt.Derive(empty, empty, 2, 1, 1, 0, long.MaxValue));
Reject(() => Scrypt.Derive(empty, empty, 2, 1, 1, int.MaxValue, long.MaxValue));
Reject(() => Scrypt.Derive(empty, empty, 2, 1, 1, 1, -1));
if (Scrypt.WorkspaceSize(2, 1, 1) != 768 || Scrypt.WorkspaceSize(32768, 1, 1) != 4194816)
    throw new InvalidOperationException("Unexpected scrypt workspace byte count");

int cases = 0;
for (string? line; (line = Console.ReadLine()) != null; cases++)
{
    string[] fields = line.Split(':');
    byte[] password = Convert.FromHexString(fields[0]);
    byte[] salt = Convert.FromHexString(fields[1]);
    int cost = int.Parse(fields[2], CultureInfo.InvariantCulture);
    int blockSize = int.Parse(fields[3], CultureInfo.InvariantCulture);
    int parallel = int.Parse(fields[4], CultureInfo.InvariantCulture);
    byte[] expected = Convert.FromHexString(fields[5]);
    long minimum = Workspace(cost, blockSize, parallel) + expected.Length;
    if (Scrypt.WorkspaceSize(cost, blockSize, parallel) + (long)expected.Length != minimum)
        throw new InvalidOperationException("Wrong computed workspace size");
    Reject(() => Scrypt.Derive(password, salt, cost, blockSize, parallel, expected.Length, minimum - 1));
    byte[] actual = Scrypt.Derive(password, salt, cost, blockSize, parallel, expected.Length, minimum);
    if (!actual.AsSpan().SequenceEqual(expected) ||
            !password.AsSpan().SequenceEqual(Convert.FromHexString(fields[0])) ||
            !salt.AsSpan().SequenceEqual(Convert.FromHexString(fields[1])))
        throw new InvalidOperationException($"Output or input preservation mismatch in case {cases}");
}
Console.WriteLine($"cases={cases}");
Console.WriteLine($"one_byte_under_budget_rejections={cases}");
Console.WriteLine("malformed_parameters_rejected=11");
