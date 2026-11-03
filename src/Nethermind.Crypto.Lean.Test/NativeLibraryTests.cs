// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using NUnit.Framework;

namespace Nethermind.Crypto.Lean.Test;

/// <summary>
/// Loads the packaged library for the current RID and checks the values Nethermind's startup check pins, so a package
/// whose ABI or verification key drifts fails here before any Nethermind bump. Nethermind's native suite covers verification.
/// </summary>
public static unsafe partial class NativeLibraryTests
{
    private const string Library = "nethermind_lean";
    private const uint ExpectedAbi = 9;
    private const string ExpectedAggregatedVk = "417152e8bd83e0dfb6f3e2bb8991e948f62c7f15d74b693b55979a40b239efa1";

    // A project reference leaves the library under runtimes/<rid>/native; a package consumer gets it beside the binary.
    static NativeLibraryTests() => NativeLibrary.SetDllImportResolver(Assembly.GetExecutingAssembly(), (name, assembly, searchPath) =>
        NativeLibrary.Load(Path.Combine(AppContext.BaseDirectory, "runtimes", RuntimeInformation.RuntimeIdentifier, "native", $"lib{name}.so"), assembly, searchPath));

    [LibraryImport(Library)]
    private static partial uint nlean_abi_version();

    [LibraryImport(Library)]
    private static partial int nlean_aggregated_vk(byte* output);

    [Test]
    public static void Abi_version_matches() => Assert.That(nlean_abi_version(), Is.EqualTo(ExpectedAbi));

    [Test]
    public static void Aggregated_verification_key_matches()
    {
        byte[] vk = new byte[32];
        fixed (byte* output = vk)
            Assert.That(nlean_aggregated_vk(output), Is.EqualTo(1));

        Assert.That(Convert.ToHexStringLower(vk), Is.EqualTo(ExpectedAggregatedVk));
    }
}
