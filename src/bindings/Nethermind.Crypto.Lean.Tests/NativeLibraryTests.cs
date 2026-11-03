// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

using System.Runtime.InteropServices;

namespace Nethermind.Crypto.Lean.Tests;

/// <summary>
/// Loads the packaged library for the current RID and checks the values Nethermind's startup check pins, so a package
/// whose ABI or verification key drifts fails here before any Nethermind bump. Nethermind's native suite covers verification.
/// </summary>
public partial class NativeLibraryTests
{
    private const string Library = "nethermind_lean";
    private const uint ExpectedAbi = 9;
    private const string ExpectedAggregatedVk = "417152e8bd83e0dfb6f3e2bb8991e948f62c7f15d74b693b55979a40b239efa1";

    // A project reference leaves the library under runtimes/<rid>/native; a package consumer gets it beside the binary.
    static NativeLibraryTests() => NativeLibrary.SetDllImportResolver(typeof(NativeLibraryTests).Assembly, static (name, assembly, searchPath) =>
        NativeLibrary.Load(Path.Combine(AppContext.BaseDirectory, "runtimes", RuntimeInformation.RuntimeIdentifier, "native", $"lib{name}.so"), assembly, searchPath));

    [LibraryImport(Library)]
    private static partial uint nlean_abi_version();

    [LibraryImport(Library)]
    private static unsafe partial int nlean_aggregated_vk(byte* output);

    [Test]
    public async Task Should_match_abi_version() => await Assert.That(nlean_abi_version()).IsEqualTo(ExpectedAbi);

    [Test]
    public async Task Should_match_aggregated_verification_key()
    {
        (int result, byte[] vk) = GetAggregatedVk();

        await Assert.That(result).IsEqualTo(1);
        await Assert.That(Convert.ToHexStringLower(vk)).IsEqualTo(ExpectedAggregatedVk);
    }

    private static unsafe (int Result, byte[] Vk) GetAggregatedVk()
    {
        byte[] vk = new byte[32];

        fixed (byte* output = vk)
            return (nlean_aggregated_vk(output), vk);
    }
}
