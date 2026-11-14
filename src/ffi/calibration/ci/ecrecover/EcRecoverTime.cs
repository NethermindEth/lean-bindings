// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT
//
// Uncached time of Nethermind's ecrecover precompile per call. The precompile keeps the last input and its result
// per thread, so repeating one input (as Nethermind.Precompiles.Benchmark does) times a cache hit; this cycles through
// distinct valid signatures so every call recovers. ecrecover-bench.sh copies it next to a Nethermind checkout and
// rewrites the project path. Prints `RESULT {...}` with the median, min and max microseconds per call.
#:project NETHERMIND/src/Nethermind/Nethermind.Evm.Precompiles/Nethermind.Evm.Precompiles.csproj
#:property Configuration=Release
#:property PublishAot=false

using System;
using System.Diagnostics;
using System.Linq;
using Nethermind.Core.Crypto;
using Nethermind.Crypto;
using Nethermind.Evm.Precompiles;

const int N = 512, Reps = 9;
Random rnd = new(1);
Ecdsa ecdsa = new();
byte[][] inputs = new byte[N][];
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
    inputs[i] = input;
}

double Pass()
{
    Stopwatch sw = Stopwatch.StartNew();
    for (int i = 0; i < N; i++)
    {
        if (ECRecoverPrecompile.Instance.Run(inputs[i], null!).Data is not { Length: 32 })
            throw new InvalidOperationException("recovery failed");
    }
    return sw.Elapsed.TotalMicroseconds / N;
}

Pass();
double[] us = Enumerable.Range(0, Reps).Select(_ => Pass()).OrderBy(x => x).ToArray();
Console.WriteLine($"RESULT {{\"calls\":{N},\"reps\":{Reps},\"median_us\":{us[Reps / 2]:F3},\"min_us\":{us[0]:F3},\"max_us\":{us[^1]:F3}}}");
