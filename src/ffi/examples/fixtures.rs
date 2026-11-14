// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT
use nethermind_lean::{
    ANY_INPUT_PROGRAM, abi_aggregated_vk, batch_hash, keccak, prove_stark, verification_key,
};
use rec_aggregation::Guest;
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
        // `key ‖ witness`: a NiceTry v2 signature, or a leanSTARK proof of the accept-all program on the message itself,
        // the statement EIP-8288's guest takes.
        let output_bytes = if directory == "--prove-stark" {
            let (witness, key) = prove_stark(Guest::Base, ANY_INPUT_PROGRAM, &message).unwrap();
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
    // Guest 0 keys a program by its flat table digest and takes a proof of the bare claim.
    let (witness, key) = prove_stark(Guest::Base, ANY_INPUT_PROGRAM, &data_hash).unwrap();
    save("stark-key.bin", &key);
    save("stark-message.bin", &data_hash);
    save("stark-proof.bin", &witness);
    // Guest 1 keys a program by `get_vk_hash` of its committed bytecode key and takes a proof of `get_claim_hash(claim)`.
    let (claim_witness, batched_key) =
        prove_stark(Guest::Batched, ANY_INPUT_PROGRAM, &batch_hash(&[data_hash])).unwrap();
    assert_ne!(batched_key, key);
    save("stark-batched-key.bin", &batched_key);
    save("stark-claim-proof.bin", &claim_witness);
    save_commitment_vectors(&save, &data_hash, &batched_key, &claim_witness);
    // A two-claim batch leaf and each claim's singleton proof, all under guest 1's key above.
    let mut claims = [keccak(b"batch claim 0"), keccak(b"batch claim 1")];
    claims.sort();
    let (batch, batch_key) = prove_stark(Guest::Batched, ANY_INPUT_PROGRAM, &batch_hash(&claims)).unwrap();
    assert_eq!(batch_key, batched_key);
    save("stark-batch-claims.bin", &claims.concat());
    save("stark-batch-proof.bin", &batch);
    for (index, claim) in claims.iter().enumerate() {
        let (single, _) = prove_stark(Guest::Batched, ANY_INPUT_PROGRAM, &batch_hash(&[*claim])).unwrap();
        save(&format!("stark-batch-singleton-{index}.bin"), &single);
    }
    for (guest, file) in [
        (Guest::Base, "aggregated-key.bin"),
        (Guest::Batched, "aggregated-batched-key.bin"),
    ] {
        let key = abi_aggregated_vk(guest);
        save(file, &key);
        println!(
            "AGGREGATED_VK {guest:?}={}",
            key.iter().map(|b| format!("{b:02x}")).collect::<String>()
        );
    }
}

/// Key-hash and key-opening consistency vectors (`crates/rec_aggregation/EIP8288-PROFILE.md`) for `stark-claim-proof.bin`'s
/// guest 1 dependency, whose witness is `kgen ‖ root ‖ ood ‖ proof`: `stark-key-hash-vectors.txt` spells out the derivation of
/// its `program_commitment` and ethereum/EIPs#12664 `get_vk_hash` of it, the key, and each `stark-key-opening-wrong-*.bin`
/// is a `key ‖ witness` pair with `ood` or the root tampered and the key recomputed over it, which verification must
/// reject.
fn save_commitment_vectors(save: &dyn Fn(&str, &[u8]), data_hash: &[u8; 32], key: &[u8; 32], witness: &[u8]) {
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let limbs = |e: verifier::E| format!("{:016x} {:016x} {:016x}", e.c0, e.c1, e.c2);
    let kgen = witness[0] as usize;
    let root: [u8; 32] = witness[1..33].try_into().unwrap();
    let ood: [u8; 32] = witness[33..65].try_into().unwrap();
    let commitment = verifier::committed_key(kgen, &root, &ood);
    let vk_hash = keccak(&[&b"EIP8288:vk:v1"[..], &commitment[..]].concat());
    assert_eq!(vk_hash, *key, "the key is the derivation below");
    let program = lean_compiler::compile(&lean_compiler::parse(ANY_INPUT_PROGRAM).unwrap());
    let table: Vec<u8> = leanvm_core::cpu::bytecode_table(program.prog())
        .iter()
        .flat_map(|word| word.0.to_le_bytes())
        .collect();
    let mut text = format!(
        "# leanSTARK EIP-8288 profile v1. program_commitment = keccak256(\"leanvm-commit-1\" || u8 kgen || root || ood);\n\
         # ood_point = {} sponge challenges, IV root, public input \"leanvm-ood-pt-1\" || u8 kgen || 16 zero bytes;\n\
         # vk_hash = keccak256(\"EIP8288:vk:v1\" || program_commitment). Limbs are c0 c1 c2 of y^0, y^1, y^2.\n\
         # The witness proves statement = get_claim_hash(data_hash) = keccak256(\"EIP8288:batch:v1\" || data_hash).\n\
         data_hash {}\nstatement {}\ntable {}\nkgen {kgen}\nroot {}\nood {}\nprogram_commitment {}\nvk_hash {}\n",
        verifier::MIN_STACKED_LOG,
        hex(data_hash),
        hex(&batch_hash(&[*data_hash])),
        hex(&table),
        hex(&root),
        hex(&ood),
        hex(&commitment),
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
        let tampered_key = rec_aggregation::vk_hash(&verifier::committed_key(kgen, &root, &ood));
        assert!(!rec_aggregation::verify_generic(data_hash, &tampered_key, &tampered), "{name} is rejected");
        save(name, &[&tampered_key[..], &tampered[..]].concat());
    }
}
