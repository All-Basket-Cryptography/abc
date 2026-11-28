using Abc.Cryptography;

static void Reject(Action operation)
{
    try { operation(); }
    catch (ArgumentException) { return; }
    throw new InvalidOperationException("Invalid Argon2id parameter accepted");
}

byte[] empty = [];
Reject(() => Argon2id.WorkspaceBytes(8, 0));
Reject(() => Argon2id.WorkspaceBytes(31, 4));
Reject(() => Argon2id.WorkspaceBytes(int.MaxValue, 1 << 24));
Reject(() => Argon2id.Derive(empty, new byte[7], 8, 1, 1, 4, long.MaxValue));
Reject(() => Argon2id.Derive(empty, new byte[8], 8, 0, 1, 4, long.MaxValue));
Reject(() => Argon2id.Derive(empty, new byte[8], 8, 1, 1, 3, long.MaxValue));
int cases = 0;
for (string? line; (line = Console.ReadLine()) != null; cases++)
{
    string[] row = line.Split(':');
    int memory = int.Parse(row[0]);
    int passes = int.Parse(row[1]);
    int lanes = int.Parse(row[2]);
    int length = int.Parse(row[3]);
    var inputs = row[4..8].Select(Convert.FromHexString).ToArray();
    byte[] expected = Convert.FromHexString(row[8]);
    long workspace = (memory - memory % (4L * lanes)) * 1024;
    if (Argon2id.WorkspaceBytes(memory, lanes) != workspace)
        throw new InvalidOperationException("Unexpected rounded Argon2id workspace size");
    Reject(() => Argon2id.Derive(inputs[0], inputs[1], memory, passes, lanes, length, workspace + length - 1,
        inputs[2], inputs[3]));
    byte[] tag = Argon2id.Derive(inputs[0], inputs[1], memory, passes, lanes, length, workspace + length,
        inputs[2], inputs[3]);
    if (!tag.SequenceEqual(expected) || inputs.Where((bytes, i) => !bytes.SequenceEqual(
        Convert.FromHexString(row[4 + i]))).Any())
        throw new InvalidOperationException($"Incorrect Argon2id tag or mutated caller inputs at fixture {cases}");
}
Console.WriteLine(cases);
