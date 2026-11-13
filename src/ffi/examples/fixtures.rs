// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT
use nethermind_lean::{ANY_INPUT_PROGRAM, aggregated_vk, keccak, prove_stark, verification_key};
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
        // `key ‖ witness`: a NiceTry v2 signature, or a leanSTARK proof of the accept-all program on the message.
        let output_bytes = if directory == "--prove-stark" {
            let (witness, key) = prove_stark(ANY_INPUT_PROGRAM, &message).unwrap();
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
    let public_input = [9; 32];
    let (witness, key) = prove_stark(ANY_INPUT_PROGRAM, &public_input).unwrap();
    save("stark-key.bin", &key);
    save("stark-message.bin", &public_input);
    save("stark-proof.bin", &witness);
    save_commitment_vectors(&save, &public_input, &key, &witness);
    let key = aggregated_vk();
    save("aggregated-key.bin", &key);
    println!(
        "AGGREGATED_VK={}",
        key.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
}

/// Key-hash and key-opening consistency vectors (`crates/rec_aggregation/EIP8288-PROFILE.md`) for `stark-proof.bin`'s
/// dependency, whose witness is `kgen ‖ root ‖ ood ‖ proof`: `stark-key-hash-vectors.txt` spells out the derivation of
/// its `program_commitment` and EIP-8288 `get_vk_hash` of it, and each `stark-key-opening-wrong-*.bin` is a
/// `program_commitment ‖ witness` pair with `ood` or the root tampered and the commitment recomputed over it, which
/// verification must reject.
fn save_commitment_vectors(save: &dyn Fn(&str, &[u8]), data_hash: &[u8; 32], key: &[u8; 32], witness: &[u8]) {
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let limbs = |e: verifier::E| format!("{:016x} {:016x} {:016x}", e.c0, e.c1, e.c2);
    let kgen = witness[0] as usize;
    let root: [u8; 32] = witness[1..33].try_into().unwrap();
    let ood: [u8; 32] = witness[33..65].try_into().unwrap();
    assert_eq!(verifier::committed_key(kgen, &root, &ood), *key, "the key is the derivation below");
    let program = lean_compiler::compile(&lean_compiler::parse(ANY_INPUT_PROGRAM).unwrap());
    let table: Vec<u8> = leanvm_core::cpu::bytecode_table(program.prog())
        .iter()
        .flat_map(|word| word.0.to_le_bytes())
        .collect();
    let vk_hash = keccak(&[&b"EIP8288:vk:v1"[..], &key[..]].concat());
    let mut text = format!(
        "# leanSTARK EIP-8288 profile v1. program_commitment = keccak256(\"leanvm-commit-1\" || u8 kgen || root || ood);\n\
         # ood_point = {} sponge challenges, IV root, public input \"leanvm-ood-pt-1\" || u8 kgen || 16 zero bytes;\n\
         # vk_hash = keccak256(\"EIP8288:vk:v1\" || program_commitment). Limbs are c0 c1 c2 of y^0, y^1, y^2.\n\
         data_hash {}\ntable {}\nkgen {kgen}\nroot {}\nood {}\nprogram_commitment {}\nvk_hash {}\n",
        verifier::MIN_STACKED_LOG,
        hex(data_hash),
        hex(&table),
        hex(&root),
        hex(&ood),
        hex(key),
        hex(&vk_hash),
    );
    for (j, coordinate) in verifier::committed_ood_point(kgen, &root).into_iter().enumerate() {
        text += &format!("ood_point[{j}] {}\n", limbs(coordinate));
    }
    save("stark-key-hash-vectors.txt", text.as_bytes());
    for (name, at) in [("stark-key-opening-wrong-ood.bin", 33), ("stark-key-opening-wrong-root.bin", 1)] {
        let mut tampered = witness.to_vec();
        tampered[at] ^= 1;
        let root: [u8; 32] = tampered[1..33].try_into().unwrap();
        let ood: [u8; 32] = tampered[33..65].try_into().unwrap();
        let tampered_key = verifier::committed_key(kgen, &root, &ood);
        assert!(!rec_aggregation::verify_generic(data_hash, &tampered_key, &tampered), "{name} is rejected");
        save(name, &[&tampered_key[..], &tampered[..]].concat());
    }
}
