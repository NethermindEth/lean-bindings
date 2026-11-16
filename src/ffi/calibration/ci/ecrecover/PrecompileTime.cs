// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT
//
// Per-call times of Nethermind's precompiles used as baselines for native verification: ecrecover (3,000 gas), the
// EIP-2537 BLS12-381 pairing check, the EIP-4844 KZG point evaluation (50,000 gas) and the EIP-7951 P-256 verify
// (6,900 gas). ecrecover keeps its last input and result per thread, so repeating one input (as
// Nethermind.Precompiles.Benchmark does) times a cache hit: it and P-256 cycle through distinct valid signatures.
// The pairing check has no cache and runs Nethermind's own benchmark vectors; point evaluation, distinct openings. ecrecover-bench.sh
// copies this next to a Nethermind checkout and rewrites the project path; the vectors directory is the first argument.
// Prints one `RESULT {...}` line per baseline: median, min and max microseconds per call, and the gas it is charged.
#:project NETHERMIND/src/Nethermind/Nethermind.Evm.Precompiles/Nethermind.Evm.Precompiles.csproj
#:property Configuration=Release
#:property PublishAot=false

using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using CkzgLib;
using Nethermind.Core.Crypto;
using Nethermind.Core.Extensions;
using Nethermind.Crypto;
using Nethermind.Evm.Precompiles;

const int N = 512, Reps = 9;
string vectors = args.Length > 0 ? args[0] : "vectors";
Random rnd = new(1);

void Time(string name, IPrecompile precompile, byte[][] inputs, ulong gas, int expectLength)
{
    double Pass()
    {
        Stopwatch sw = Stopwatch.StartNew();
        foreach (byte[] input in inputs)
        {
            if (precompile.Run(input, null!).Data is not { } data || data.Length != expectLength)
                throw new InvalidOperationException($"{name} failed");
        }
        return sw.Elapsed.TotalMicroseconds / inputs.Length;
    }

    Pass();
    double[] us = Enumerable.Range(0, Reps).Select(_ => Pass()).OrderBy(x => x).ToArray();
    Console.WriteLine($"RESULT {{\"name\":\"{name}\",\"gas\":{gas},\"calls\":{inputs.Length},\"reps\":{Reps}," +
                      $"\"median_us\":{us[Reps / 2]:F3},\"min_us\":{us[0]:F3},\"max_us\":{us[^1]:F3}}}");
}

// ecrecover: distinct valid signatures.
Ecdsa ecdsa = new();
byte[][] ecr = new byte[N][];
for (int i = 0; i < N; i++)
{
    byte[] key = new byte[32];
    rnd.NextBytes(key);
    key[0] = 1;
    byte[] msg = new byte[32];
    rnd.NextBytes(msg);
    Signature sig = ecdsa.Sign(new PrivateKey(key), new ValueHash256(msg));
    byte[] input = new byte[128];
    msg.CopyTo(input, 0);
    input[63] = (byte)(27 + sig.RecoveryId);
    sig.Bytes.CopyTo(input.AsSpan(64));
    ecr[i] = input;
}
Time("ecrecover", ECRecoverPrecompile.Instance, ecr, 3000, 32);

// P-256 (EIP-7951): distinct valid signatures over random hashes.
byte[][] p256 = new byte[N][];
for (int i = 0; i < N; i++)
{
    using ECDsa k = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    ECParameters q = k.ExportParameters(false);
    byte[] hash = new byte[32];
    rnd.NextBytes(hash);
    byte[] rs = k.SignHash(hash);
    p256[i] = [.. hash, .. rs, .. q.Q.X!, .. q.Q.Y!];
}
Time("p256verify", SecP256r1Precompile.Instance, p256, 6900, 32);

// BLS12-381 pairing check (EIP-2537): Nethermind's vectors of 1 to 8 pairs, gas 37,700 + 32,600 per pair.
foreach (string file in Directory.GetFiles(Path.Combine(vectors, "blspairingcheck", "current"), "*.csv").Order())
{
    byte[] input = Bytes.FromHexString(File.ReadAllLines(file).First(l => l.Length > 0).Split(',')[0]);
    int pairs = input.Length / 384;
    Time($"bls12381_pairing_{pairs}", Bls12381PairingCheckPrecompile.Instance, [input], 37700UL + 32600UL * (ulong)pairs, 32);
}

// KZG point evaluation (EIP-4844): distinct valid openings of random blobs. (The benchmark repository's own vector
// does not verify against the mainnet trusted setup.)
await KzgPolynomialCommitments.InitializeAsync();
nint setup = Ckzg.LoadTrustedSetup(Path.Combine(AppContext.BaseDirectory, "kzg_trusted_setup.txt"), 0);
byte[][] kzg = new byte[16][];
for (int i = 0; i < kzg.Length; i++)
{
    byte[] blob = new byte[Ckzg.BytesPerBlob];
    rnd.NextBytes(blob);
    for (int j = 0; j < blob.Length; j += 32)
        blob[j] = 0;
    byte[] z = new byte[32];
    rnd.NextBytes(z);
    z[0] = 0;
    byte[] commitment = new byte[Ckzg.BytesPerCommitment], proof = new byte[Ckzg.BytesPerProof], y = new byte[32], hash = new byte[32];
    Ckzg.BlobToKzgCommitment(commitment, blob, setup);
    Ckzg.ComputeKzgProof(proof, y, blob, z, setup);
    KzgPolynomialCommitments.TryComputeCommitmentHashV1(commitment, hash);
    kzg[i] = [.. hash, .. z, .. y, .. commitment, .. proof];
}
Time("kzg_point_evaluation", KzgPointEvaluationPrecompile.Instance, kzg, 50000, 64);
