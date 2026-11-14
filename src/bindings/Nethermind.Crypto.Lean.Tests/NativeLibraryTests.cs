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
    private const uint ExpectedAbi = 12;
    private const string ExpectedAggregatedVk = "f6f37690cf7241c9ea24392f349867acc1c8e06034e8ce149e2f11a25eec56f9";
    // Proof bytes, dependencies, recursive children, NiceTry v2 witness bytes, aggregation input bytes, leanSTARK claims
    // per list, leanSTARK instructions.
    private static readonly uint[] ExpectedLimits = [8 * 1024 * 1024, 256, 16, 32 + 6176, 18 * 1024 * 1024, 16, 2048];

    // A project reference leaves the library under runtimes/<rid>/native; a package consumer gets it beside the binary.
    static NativeLibraryTests() => NativeLibrary.SetDllImportResolver(typeof(NativeLibraryTests).Assembly, static (name, assembly, searchPath) =>
        NativeLibrary.Load(Path.Combine(AppContext.BaseDirectory, "runtimes", RuntimeInformation.RuntimeIdentifier, "native", $"lib{name}.so"), assembly, searchPath));

    [LibraryImport(Library)]
    private static partial uint nlean_abi_version();

    [LibraryImport(Library)]
    private static unsafe partial int nlean_aggregated_vk(byte* output);

    [LibraryImport(Library)]
    private static unsafe partial int nlean_limits(uint* output, nuint length);

    [LibraryImport(Library)]
    private static unsafe partial int nlean_verify_leansphincs(byte* data, byte* vk, byte* witness, nuint length);

    [LibraryImport(Library)]
    private static unsafe partial int nlean_verify_leanstark(byte* data, byte* vk, byte* witness, nuint length);

    private static byte[] Vector(string name) => File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "lean-vectors", name));

    [Test]
    public async Task Should_match_abi_version() => await Assert.That(nlean_abi_version()).IsEqualTo(ExpectedAbi);

    [Test]
    public async Task Should_match_aggregated_verification_key()
    {
        (int result, byte[] vk) = GetAggregatedVk();

        await Assert.That(result).IsEqualTo(1);
        await Assert.That(Convert.ToHexStringLower(vk)).IsEqualTo(ExpectedAggregatedVk);
        // The packaged vectors come from the same build.
        await Assert.That(Convert.ToHexStringLower(Vector("aggregated-key.bin"))).IsEqualTo(ExpectedAggregatedVk);
    }

    [Test]
    public async Task Should_match_limits()
    {
        uint[] limits = new uint[ExpectedLimits.Length];
        int result = GetLimits(limits);

        await Assert.That(result).IsEqualTo(1);
        await Assert.That(limits).IsEquivalentTo(ExpectedLimits);
    }

    [Test]
    [Arguments("sphincs-message.bin", "sphincs-key.bin", "sphincs-signature.bin", false)]
    [Arguments("stark-message.bin", "stark-key.bin", "stark-proof.bin", true)]
    public async Task Should_verify_vector_and_reject_a_flipped_byte(string message, string key, string witness, bool leanStark)
    {
        byte[] data = Vector(message), vk = Vector(key), proof = Vector(witness);

        await Assert.That(Verify(leanStark, data, vk, proof)).IsEqualTo(1);
        proof[^1] ^= 1;
        await Assert.That(Verify(leanStark, data, vk, proof)).IsEqualTo(0);
    }

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

    private static unsafe int Verify(bool leanStark, byte[] data, byte[] vk, byte[] witness)
    {
        fixed (byte* d = data)
        fixed (byte* k = vk)
        fixed (byte* w = witness)
            return leanStark
                ? nlean_verify_leanstark(d, k, w, (nuint)witness.Length)
                : nlean_verify_leansphincs(d, k, w, (nuint)witness.Length);
    }

    private static unsafe int GetLimits(uint[] limits)
    {
        fixed (uint* output = limits)
            return nlean_limits(output, (nuint)limits.Length);
    }

    private static unsafe (int Result, byte[] Vk) GetAggregatedVk()
    {
        byte[] vk = new byte[32];

        fixed (byte* output = vk)
            return (nlean_aggregated_vk(output), vk);
    }
}
