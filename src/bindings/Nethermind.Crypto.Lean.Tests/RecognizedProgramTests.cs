// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace Nethermind.Crypto.Lean.Tests;

/// <summary>
/// Checks EIP-8437 mode 2's recognized programs through the C ABI against the packaged <c>raw-vectors.json</c>: their keys,
/// every vector's native verdict and claim, and a one-signature leaf that the batched guest verifies as a direct witness.
/// </summary>
public partial class RecognizedProgramTests
{
    private const string Library = "nethermind_lean";
    private const uint BatchedGuest = 1;
    private const uint SlhDsa = 3;

    static RecognizedProgramTests() => NativeLibrary.SetDllImportResolver(typeof(RecognizedProgramTests).Assembly, static (name, assembly, searchPath) =>
        NativeLibrary.Load(Path.Combine(AppContext.BaseDirectory, "runtimes", RuntimeInformation.RuntimeIdentifier, "native", $"lib{name}.so"), assembly, searchPath));

    [LibraryImport(Library)]
    private static unsafe partial int nlean_recognized_key(uint profile, byte* output);

    [LibraryImport(Library)]
    private static unsafe partial int nlean_verify_raw(uint profile, byte* pk, nuint pkLength, byte* message, byte* signature, nuint signatureLength, byte* claim);

    [LibraryImport(Library)]
    private static unsafe partial int nlean_prove_raw_leaf(uint profile, byte* input, nuint inputLength, byte** output, nuint* outputLength);

    [LibraryImport(Library)]
    private static unsafe partial int nlean_verify_leanstark(uint guest, byte* data, byte* vk, byte* witness, nuint length);

    [LibraryImport(Library)]
    private static unsafe partial void nlean_free(byte* proof, nuint length);

    private sealed record Profile(uint Id, string Name, byte[] Key);

    private sealed record Vector(uint Profile, string Label, byte[] PublicKey, byte[] Message, byte[] Signature, byte[]? Claim);

    private static readonly Lazy<(Profile[] Profiles, Vector[] Vectors)> Vectors = new(Load);

    private static (Profile[], Vector[]) Load()
    {
        using JsonDocument json = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "lean-vectors", "raw-vectors.json")));
        static byte[] Hex(JsonElement e) => Convert.FromHexString(e.GetString()![2..]);
        Profile[] profiles = [.. json.RootElement.GetProperty("profiles").EnumerateArray()
            .Select(p => new Profile(p.GetProperty("id").GetUInt32(), p.GetProperty("name").GetString()!, Hex(p.GetProperty("key"))))];
        Vector[] vectors = [.. json.RootElement.GetProperty("vectors").EnumerateArray()
            .Select(v => new Vector(v.GetProperty("profile").GetUInt32(), v.GetProperty("label").GetString()!, Hex(v.GetProperty("publicKey")),
                Hex(v.GetProperty("message")), Hex(v.GetProperty("signature")),
                v.GetProperty("claim").ValueKind == JsonValueKind.Null ? null : Hex(v.GetProperty("claim"))))];
        return (profiles, vectors);
    }

    [Test]
    public async Task Should_match_every_recognized_key()
    {
        await Assert.That(Vectors.Value.Profiles.Length).IsEqualTo(3);
        foreach (Profile profile in Vectors.Value.Profiles)
        {
            (int result, byte[] key) = RecognizedKey(profile.Id);
            await Assert.That(result).IsEqualTo(1);
            await Assert.That(key).IsEquivalentTo(profile.Key);
        }
    }

    [Test]
    [Arguments(0u)]
    [Arguments(4u)]
    public async Task Should_reject_an_unknown_profile(uint profile)
    {
        await Assert.That(RecognizedKey(profile).Result).IsEqualTo(0);
        Vector honest = Vectors.Value.Vectors[0];
        await Assert.That(VerifyRaw(profile, honest).Result).IsEqualTo(0);
    }

    [Test]
    public async Task Should_reach_every_vector_verdict()
    {
        await Assert.That(Vectors.Value.Vectors.Length).IsGreaterThan(30);
        foreach (Vector vector in Vectors.Value.Vectors)
        {
            (int result, byte[] claim) = VerifyRaw(vector.Profile, vector);
            await Assert.That(result).IsEqualTo(vector.Claim is null ? 0 : 1).Because(vector.Label);
            if (vector.Claim is not null) await Assert.That(claim).IsEquivalentTo(vector.Claim);
        }
    }

    [Test]
    public async Task Should_prove_a_leaf_the_batched_guest_takes_as_a_direct_witness()
    {
        Vector honest = Vectors.Value.Vectors.First(v => v.Profile == SlhDsa && v.Claim is not null);
        byte[] key = Vectors.Value.Profiles.Single(p => p.Id == SlhDsa).Key;
        (int result, byte[] witness) = ProveLeaf(SlhDsa, honest);
        await Assert.That(result).IsEqualTo(1);
        await Assert.That(VerifyLeanStark(honest.Claim!, key, witness)).IsEqualTo(1);

        byte[] otherClaim = (byte[])honest.Claim!.Clone();
        otherClaim[0] ^= 1;
        await Assert.That(VerifyLeanStark(otherClaim, key, witness)).IsEqualTo(0);
    }

    [Test]
    public async Task Should_refuse_to_prove_a_rejected_signature()
    {
        Vector rejected = Vectors.Value.Vectors.First(v => v.Profile == SlhDsa && v.Claim is null);
        await Assert.That(ProveLeaf(SlhDsa, rejected).Result).IsEqualTo(0);
    }

    private static unsafe (int Result, byte[] Key) RecognizedKey(uint profile)
    {
        byte[] key = new byte[32];
        fixed (byte* k = key)
            return (nlean_recognized_key(profile, k), key);
    }

    private static unsafe (int Result, byte[] Claim) VerifyRaw(uint profile, Vector vector)
    {
        byte[] claim = new byte[32];
        fixed (byte* pk = vector.PublicKey)
        fixed (byte* m = vector.Message)
        fixed (byte* s = vector.Signature)
        fixed (byte* c = claim)
            return (nlean_verify_raw(profile, pk, (nuint)vector.PublicKey.Length, m, s, (nuint)vector.Signature.Length, c), claim);
    }

    private static unsafe (int Result, byte[] Witness) ProveLeaf(uint profile, Vector vector)
    {
        byte[] input = new byte[4 + 4 + vector.PublicKey.Length + 32 + 4 + vector.Signature.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(input, 1);
        int at = 4;
        BinaryPrimitives.WriteUInt32LittleEndian(input.AsSpan(at), (uint)vector.PublicKey.Length);
        vector.PublicKey.CopyTo(input, at += 4);
        vector.Message.CopyTo(input, at += vector.PublicKey.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(input.AsSpan(at += 32), (uint)vector.Signature.Length);
        vector.Signature.CopyTo(input, at + 4);
        byte* output = null;
        nuint length = 0;
        int result;
        fixed (byte* i = input)
            result = nlean_prove_raw_leaf(profile, i, (nuint)input.Length, &output, &length);
        if (result != 1) return (result, []);
        byte[] witness = new ReadOnlySpan<byte>(output, (int)length).ToArray();
        nlean_free(output, length);
        return (result, witness);
    }

    private static unsafe int VerifyLeanStark(byte[] claim, byte[] key, byte[] witness)
    {
        fixed (byte* d = claim)
        fixed (byte* k = key)
        fixed (byte* w = witness)
            return nlean_verify_leanstark(BatchedGuest, d, k, w, (nuint)witness.Length);
    }
}
