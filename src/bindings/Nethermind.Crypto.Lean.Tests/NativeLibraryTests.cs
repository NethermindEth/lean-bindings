// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Nethermind.Crypto.Lean.Tests;

/// <summary>
/// Loads the packaged library for the current RID and checks the values consumers pin (ABI, aggregated verification key,
/// limits), then verifies the packaged test vectors through the <c>nlean_*</c> C ABI, with no consumer checkout.
/// </summary>
public partial class NativeLibraryTests
{
    private const string Library = "nethermind_lean";
    private const uint ExpectedAbi = 16;
    // EIP-8288's guest (0), the ABI 12 package's unchanged, and the one with ethereum/EIPs#12664 batch pricing (1).
    private const string ExpectedAggregatedVk = "f7cf74585d02043051f0575c23c6b441b0b08ac9e273f5e989c5984b8a4ac0e5";
    private const string ExpectedBatchedAggregatedVk = "df3a802307fe9831311df1288864e5ab0e672b19a224f6b23a374fc873a69828";
    // Proof bytes, dependencies, inner proofs per step, NiceTry v2 witness bytes, aggregation input bytes, leanSTARK
    // dependencies per list (guest 0) or claims per batch leaf (guest 1), leanSTARK instructions.
    private static readonly uint[] ExpectedLimits = [8 * 1024 * 1024, 256, 16, 32 + 6176, 18 * 1024 * 1024, 16, 2048];
    private static readonly uint[] ExpectedBatchedLimits = [8 * 1024 * 1024, 256, 12, 32 + 6176, 18 * 1024 * 1024, 256, 2048];

    // A project reference leaves the library under runtimes/<rid>/native; a package consumer gets it beside the binary.
    static NativeLibraryTests() => NativeLibrary.SetDllImportResolver(typeof(NativeLibraryTests).Assembly, static (name, assembly, searchPath) =>
        NativeLibrary.Load(Path.Combine(AppContext.BaseDirectory, "runtimes", RuntimeInformation.RuntimeIdentifier, "native", $"lib{name}.so"), assembly, searchPath));

    [LibraryImport(Library)]
    private static partial uint nlean_abi_version();

    [LibraryImport(Library)]
    private static unsafe partial int nlean_aggregated_vk(uint guest, byte* output);

    [LibraryImport(Library)]
    private static unsafe partial int nlean_limits(uint guest, uint* output, nuint length);

    [LibraryImport(Library)]
    private static unsafe partial int nlean_verify_leansphincs(byte* data, byte* vk, byte* witness, nuint length);

    [LibraryImport(Library)]
    private static unsafe partial int nlean_verify_leanstark(uint guest, byte* data, byte* vk, byte* witness, nuint length);

    private static byte[] Vector(string name) => File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "lean-vectors", name));

    [Test]
    public async Task Should_match_abi_version() => await Assert.That(nlean_abi_version()).IsEqualTo(ExpectedAbi);

    [Test]
    [Arguments(0u, ExpectedAggregatedVk, "aggregated-key.bin")]
    [Arguments(1u, ExpectedBatchedAggregatedVk, "aggregated-batched-key.bin")]
    public async Task Should_match_aggregated_verification_key(uint guest, string expected, string vector)
    {
        (int result, byte[] vk) = GetAggregatedVk(guest);

        await Assert.That(result).IsEqualTo(1);
        await Assert.That(Convert.ToHexStringLower(vk)).IsEqualTo(expected);
        // The packaged vectors come from the same build.
        await Assert.That(Convert.ToHexStringLower(Vector(vector))).IsEqualTo(expected);
    }

    [Test]
    public async Task Should_reject_an_unknown_guest() => await Assert.That(GetAggregatedVk(2).Result).IsEqualTo(0);

    [Test]
    [Arguments(0u)]
    [Arguments(1u)]
    public async Task Should_match_limits(uint guest)
    {
        uint[] expected = guest == 0 ? ExpectedLimits : ExpectedBatchedLimits;
        uint[] limits = new uint[expected.Length];
        int result = GetLimits(guest, limits);

        await Assert.That(result).IsEqualTo(1);
        await Assert.That(limits).IsEquivalentTo(expected);
    }

    [Test]
    [Arguments("sphincs-message.bin", "sphincs-key.bin", "sphincs-signature.bin", false, 0u)]
    [Arguments("stark-message.bin", "stark-key.bin", "stark-proof.bin", true, 0u)]
    [Arguments("stark-message.bin", "stark-key.bin", "stark-claim-proof.bin", true, 1u)]
    public async Task Should_verify_vector_and_reject_a_flipped_byte(string message, string key, string witness, bool leanStark, uint guest)
    {
        byte[] data = Vector(message), vk = Vector(key), proof = Vector(witness);

        await Assert.That(Verify(leanStark, data, vk, proof, guest)).IsEqualTo(1);
        proof[^1] ^= 1;
        await Assert.That(Verify(leanStark, data, vk, proof, guest)).IsEqualTo(0);
    }

    // Guest 0 takes a direct leanSTARK proof of the bare claim, guest 1 one of get_claim_hash(claim); neither takes the other's.
    [Test]
    [Arguments("stark-proof.bin", 1u)]
    [Arguments("stark-claim-proof.bin", 0u)]
    [Arguments("stark-claim-proof.bin", 2u)]
    public async Task Should_reject_a_leanstark_vector_under_another_guest(string witness, uint guest) =>
        await Assert.That(Verify(true, Vector("stark-message.bin"), Vector("stark-key.bin"), Vector(witness), guest)).IsEqualTo(0);

    [Test]
    [Arguments("--sign-message", false)]
    [Arguments("--prove-stark", true)]
    public async Task Should_verify_a_witness_from_the_packaged_fixtures_tool(string mode, bool leanStark)
    {
        byte[] message = Convert.FromHexString("8e1f2c3d4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0");
        string output = Path.GetTempFileName();
        try
        {
            using Process process = Process.Start(new ProcessStartInfo(Path.Combine(AppContext.BaseDirectory, "lean-vectors", "fixtures"))
            {
                ArgumentList = { mode, Convert.ToHexString(message), output },
            })!;
            await process.WaitForExitAsync();
            await Assert.That(process.ExitCode).IsEqualTo(0);

            // `key ‖ witness`; a NiceTry v2 witness keeps its key prefix, a leanSTARK witness is the proof alone.
            byte[] keyAndWitness = File.ReadAllBytes(output);
            byte[] witness = leanStark ? keyAndWitness[32..] : keyAndWitness;
            await Assert.That(Verify(leanStark, message, keyAndWitness[..32], witness)).IsEqualTo(1);
        }
        finally
        {
            File.Delete(output);
        }
    }

    private static unsafe int Verify(bool leanStark, byte[] data, byte[] vk, byte[] witness, uint guest = 0)
    {
        fixed (byte* d = data)
        fixed (byte* k = vk)
        fixed (byte* w = witness)
            return leanStark
                ? nlean_verify_leanstark(guest, d, k, w, (nuint)witness.Length)
                : nlean_verify_leansphincs(d, k, w, (nuint)witness.Length);
    }

    private static unsafe int GetLimits(uint guest, uint[] limits)
    {
        fixed (uint* output = limits)
            return nlean_limits(guest, output, (nuint)limits.Length);
    }

    private static unsafe (int Result, byte[] Vk) GetAggregatedVk(uint guest)
    {
        byte[] vk = new byte[32];

        fixed (byte* output = vk)
            return (nlean_aggregated_vk(guest, output), vk);
    }
}
