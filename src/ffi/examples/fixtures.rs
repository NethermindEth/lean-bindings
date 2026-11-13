// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT
use nethermind_lean::{
    ANY_INPUT_PROGRAM, aggregated_vk, batch_hash, keccak, prove_stark, verification_key,
};
use signatures::lean_sphincs::{key_gen_from_seed, sign};
fn main() {
    let directory = std::env::args().nth(1).expect("fixture output directory");
    if directory == "--sign-message" || directory == "--prove-stark" {
        let mut arguments = std::env::args().skip(2);
        let hash = arguments.next().expect("32-byte message as hex");
        assert_eq!(hash.len(), 64, "message must contain 64 hex digits");
        let mut message = [0; 32];
        for (index, byte) in message.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hash[index * 2..index * 2 + 2], 16).expect("hex message");
        }
        let output = arguments.next().expect("witness output file");
        assert!(arguments.next().is_none(), "unexpected fixture arguments");
        // `key ‖ witness`: a NiceTry v2 signature, or a leanSTARK proof of the accept-all program on the message's
        // singleton batch statement.
        let output_bytes = if directory == "--prove-stark" {
            let (witness, key) = prove_stark(ANY_INPUT_PROGRAM, &batch_hash(&[message])).unwrap();
            [&key[..], &witness[..]].concat()
        } else {
            let (sk, pk) = key_gen_from_seed([42; 32]);
            let signature = sign(&sk, &message).unwrap();
            [&verification_key(&pk)[..], &signature.to_bytes()[..]].concat()
        };
        std::fs::write(output, output_bytes).unwrap();
        return;
    }
    std::fs::create_dir_all(&directory).unwrap();
    let save =
        |name: &str, bytes: &[u8]| std::fs::write(format!("{directory}/{name}"), bytes).unwrap();
    let (sk, pk) = key_gen_from_seed([42; 32]);
    let message = [7; 32];
    let sig = sign(&sk, &message).unwrap();
    save("sphincs-key.bin", &verification_key(&pk));
    save("sphincs-message.bin", &message);
    save(
        "sphincs-signature.bin",
        &[&verification_key(&pk)[..], &sig.to_bytes()[..]].concat(),
    );
    let mut multi = Vec::new();
    for index in 0u64..16 {
        let message = keccak(&index.to_le_bytes());
        multi.extend_from_slice(&message);
        multi.extend_from_slice(&verification_key(&pk));
        multi.extend_from_slice(&sign(&sk, &message).unwrap().to_bytes());
    }
    save("sphincs-multi.bin", &multi);
    let mut multi_keys = Vec::new();
    for index in 0u8..16 {
        let mut seed = [42; 32];
        seed[0] = index;
        let (sk, pk) = key_gen_from_seed(seed);
        let message = keccak(&[index]);
        multi_keys.extend_from_slice(&message);
        multi_keys.extend_from_slice(&verification_key(&pk));
        multi_keys.extend_from_slice(&sign(&sk, &message).unwrap().to_bytes());
    }
    save("sphincs-multi-keys.bin", &multi_keys);
    let data_hash = [9; 32];
    let (witness, key) = prove_stark(ANY_INPUT_PROGRAM, &batch_hash(&[data_hash])).unwrap();
    save("stark-key.bin", &key);
    save("stark-message.bin", &data_hash);
    save("stark-proof.bin", &witness);
    // A two-claim batch leaf and each claim's singleton proof, all under the key above.
    let mut claims = [keccak(b"batch claim 0"), keccak(b"batch claim 1")];
    claims.sort();
    let (batch, batch_key) = prove_stark(ANY_INPUT_PROGRAM, &batch_hash(&claims)).unwrap();
    assert_eq!(batch_key, key);
    save("stark-batch-claims.bin", &claims.concat());
    save("stark-batch-proof.bin", &batch);
    for (index, claim) in claims.iter().enumerate() {
        let (single, _) = prove_stark(ANY_INPUT_PROGRAM, &batch_hash(&[*claim])).unwrap();
        save(&format!("stark-batch-singleton-{index}.bin"), &single);
    }
    let key = aggregated_vk();
    save("aggregated-key.bin", &key);
    println!(
        "AGGREGATED_VK={}",
        key.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
}
