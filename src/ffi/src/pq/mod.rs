// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

//! Recognized signature programs (EIP-8437 mode 2): generic leaves verifying ML-DSA-44, Falcon-512 or
//! SLH-DSA-SHAKE-128s signatures over 32-byte messages, one claim per signature, and the native checks a relay runs
//! before admitting a raw signature for proving.

pub mod common;
pub mod falcon;
pub mod mldsa;
pub mod slhdsa;

use std::sync::OnceLock;

use leanvm_core::cpu::{Program, bytecode_table};
use rec_aggregation::{MAX_CLAIMS_PER_BATCH_LEAF, generic_verification_key};

use common::{Claim, Leaf, Scheme, program, prove_items};

/// A raw signature: public key, 32-byte message and signature.
pub type RawSignature<'a> = (&'a [u8], [u8; 32], &'a [u8]);

/// A recognized program, by its ABI identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    MlDsa44 = 1,
    Falcon512 = 2,
    SlhDsa128s = 3,
}

impl Profile {
    pub const ALL: [Profile; 3] = [Profile::MlDsa44, Profile::Falcon512, Profile::SlhDsa128s];

    pub fn from_id(id: u32) -> Option<Self> {
        Self::ALL.into_iter().find(|p| *p as u32 == id)
    }

    /// The EIP-8437 profile name.
    pub fn name(self) -> &'static str {
        match self {
            Profile::MlDsa44 => "mldsa44-pure-v1",
            Profile::Falcon512 => "falcon512-padded-v1",
            Profile::SlhDsa128s => "slhdsa-shake128s-pure-v1",
        }
    }

    /// The committed program and its leanSTARK key: `get_vk_hash` of its bytecode commitment.
    fn compiled(self) -> &'static (Program, [u8; 32]) {
        static PROGRAMS: [OnceLock<(Program, [u8; 32])>; 3] = [OnceLock::new(), OnceLock::new(), OnceLock::new()];
        PROGRAMS[self as usize - 1].get_or_init(|| {
            let program = match self {
                Profile::MlDsa44 => program::<mldsa::MlDsa44>(),
                Profile::Falcon512 => program::<falcon::Falcon512>(),
                Profile::SlhDsa128s => program::<slhdsa::SlhDsa128s>(),
            };
            let table: Vec<u64> = bytecode_table(program.prog()).iter().map(|w| w.0).collect();
            let key = generic_verification_key(&table).expect("a recognized program fits the generic bytecode bound");
            (program, key)
        })
    }

    /// The program's EIP-8288 verification key hash.
    pub fn key(self) -> [u8; 32] {
        self.compiled().1
    }

    /// The claim of a signature over `msg` that this profile's native check accepts, or `None`.
    pub fn verify(self, pk: &[u8], msg: &[u8; 32], sig: &[u8]) -> Option<Claim> {
        match self {
            Profile::MlDsa44 => mldsa::verified(pk, msg, sig).map(|i| mldsa::MlDsa44::claim(&i)),
            Profile::Falcon512 => falcon::verified(pk, msg, sig).map(|i| falcon::Falcon512::claim(&i)),
            Profile::SlhDsa128s => slhdsa::verified(pk, msg, sig).map(|i| slhdsa::SlhDsa128s::claim(&i)),
        }
    }

    /// Proves one leaf over `signatures`, each `(public key, message, signature)`: its sorted claims and witness under
    /// [`Profile::key`]. `Err` when a signature fails the native check, two share a claim, or the count is outside
    /// `1..=MAX_CLAIMS_PER_BATCH_LEAF`.
    pub fn prove(self, signatures: &[RawSignature]) -> Result<Leaf, ()> {
        if !(1..=MAX_CLAIMS_PER_BATCH_LEAF).contains(&signatures.len()) {
            return Err(());
        }
        let program = &self.compiled().0;
        match self {
            Profile::MlDsa44 => prove_checked::<mldsa::MlDsa44>(program, signatures, mldsa::verified),
            Profile::Falcon512 => prove_checked::<falcon::Falcon512>(program, signatures, falcon::verified),
            Profile::SlhDsa128s => prove_checked::<slhdsa::SlhDsa128s>(program, signatures, slhdsa::verified),
        }
    }
}

/// A vector's input: label, public key, message, signature and whether the native check accepts it.
type RawCase = (&'static str, Vec<u8>, [u8; 32], Vec<u8>, bool);

/// One native/leaf equivalence vector.
pub struct Vector {
    pub profile: Profile,
    pub label: &'static str,
    pub pk: Vec<u8>,
    pub msg: [u8; 32],
    pub sig: Vec<u8>,
    /// The claim when the native check accepts.
    pub claim: Option<Claim>,
}

/// Every profile's equivalence vectors, with the native verdicts this library reaches.
pub fn vectors() -> Vec<Vector> {
    let mut out = Vec::new();
    for profile in Profile::ALL {
        let inputs = match profile {
            Profile::MlDsa44 => mldsa::vector_inputs(),
            Profile::Falcon512 => falcon::vector_inputs(),
            Profile::SlhDsa128s => slhdsa::vector_inputs(),
        };
        for (label, pk, msg, sig, valid) in inputs {
            let claim = profile.verify(&pk, &msg, &sig);
            assert_eq!(claim.is_some(), valid, "{}: {label}", profile.name());
            out.push(Vector { profile, label, pk, msg, sig, claim });
        }
    }
    out
}

/// Every profile's key and [`vectors`] as JSON, for other implementations of the native check: an accepted vector
/// carries its claim, a rejected one `null`.
pub fn vectors_json() -> String {
    let hex = |bytes: &[u8]| format!("\"0x{}\"", bytes.iter().map(|b| format!("{b:02x}")).collect::<String>());
    let profiles: Vec<String> = Profile::ALL
        .iter()
        .map(|p| format!("{{\"id\":{},\"name\":\"{}\",\"key\":{}}}", *p as u32, p.name(), hex(&p.key())))
        .collect();
    let cases: Vec<String> = vectors()
        .iter()
        .map(|v| {
            format!(
                "{{\"profile\":{},\"label\":\"{}\",\"publicKey\":{},\"message\":{},\"signature\":{},\"claim\":{}}}",
                v.profile as u32,
                v.label,
                hex(&v.pk),
                hex(&v.msg),
                hex(&v.sig),
                v.claim.map_or("null".to_string(), |c| hex(&c))
            )
        })
        .collect();
    format!("{{\"profiles\":[{}],\"vectors\":[\n{}\n]}}", profiles.join(","), cases.join(",\n"))
}

fn prove_checked<S: Scheme>(
    program: &Program,
    signatures: &[RawSignature],
    verified: fn(&[u8], &[u8; 32], &[u8]) -> Option<S::Item>,
) -> Result<Leaf, ()> {
    let items = signatures
        .iter()
        .map(|(pk, msg, sig)| verified(pk, msg, sig).ok_or(()))
        .collect::<Result<Vec<_>, ()>>()?;
    let mut claims: Vec<Claim> = items.iter().map(S::claim).collect();
    claims.sort();
    if claims.windows(2).any(|w| w[0] == w[1]) {
        return Err(());
    }
    prove_items::<S>(program, items, None).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rec_aggregation::{Guest, verify_batch_leaf};

    fn of(profile: Profile) -> Vec<Vector> {
        vectors().into_iter().filter(|v| v.profile == profile).collect()
    }

    #[test]
    fn every_profile_has_accepted_and_rejected_vectors() {
        for profile in Profile::ALL {
            let vectors = of(profile);
            assert_eq!(vectors.iter().filter(|v| v.claim.is_some()).count(), 2, "{}", profile.name());
            assert!(vectors.iter().filter(|v| v.claim.is_none()).count() >= 10, "{}", profile.name());
        }
    }

    #[test]
    fn keys_are_distinct() {
        let keys: std::collections::BTreeSet<_> = Profile::ALL.iter().map(|p| p.key()).collect();
        assert_eq!(keys.len(), Profile::ALL.len());
    }

    fn accepted_vectors_prove(profile: Profile) {
        let accepted: Vec<Vector> = of(profile).into_iter().filter(|v| v.claim.is_some()).collect();
        let signatures: Vec<_> = accepted.iter().map(|v| (&v.pk[..], v.msg, &v.sig[..])).collect();
        let leaf = profile.prove(&signatures).expect("accepted signatures prove");
        let mut claims: Vec<Claim> = accepted.iter().map(|v| v.claim.unwrap()).collect();
        claims.sort();
        assert_eq!(leaf.claims, claims);
        assert!(verify_batch_leaf(Guest::Batched, &claims, &profile.key(), &leaf.witness));
    }

    #[test]
    fn falcon_accepted_vectors_prove() {
        accepted_vectors_prove(Profile::Falcon512);
    }

    #[test]
    fn slhdsa_accepted_vectors_prove() {
        accepted_vectors_prove(Profile::SlhDsa128s);
    }

    #[test]
    #[ignore = "an ML-DSA-44 leaf of two signatures needs about 10 GB"]
    fn mldsa_accepted_vectors_prove() {
        accepted_vectors_prove(Profile::MlDsa44);
    }

    #[test]
    fn prove_refuses_rejected_signatures_repeated_claims_and_empty_leaves() {
        for v in vectors().iter().filter(|v| v.claim.is_none()) {
            assert!(v.profile.prove(&[(&v.pk, v.msg, &v.sig)]).is_err(), "{}: {}", v.profile.name(), v.label);
        }
        let honest = &of(Profile::SlhDsa128s)[0];
        let signature = (&honest.pk[..], honest.msg, &honest.sig[..]);
        assert!(Profile::SlhDsa128s.prove(&[signature, signature]).is_err());
        assert!(Profile::SlhDsa128s.prove(&[]).is_err());
    }

    #[test]
    fn the_leaf_rejects_signatures_the_native_check_rejects() {
        for v in of(Profile::SlhDsa128s).iter().filter(|v| v.label.starts_with("altered") && v.label != "altered message") {
            let item = slhdsa::unchecked(&v.pk, &v.msg, &v.sig);
            let proved = prove_items::<slhdsa::SlhDsa128s>(&Profile::SlhDsa128s.compiled().0, vec![item], None);
            assert!(proved.is_err(), "slhdsa: {}", v.label);
        }
        for v in of(Profile::Falcon512).iter().filter(|v| matches!(v.label, "altered nonce" | "altered s2" | "signature over another message")) {
            let item = falcon::unchecked(&v.pk, &v.msg, &v.sig);
            let proved = prove_items::<falcon::Falcon512>(&Profile::Falcon512.compiled().0, vec![item], None);
            assert!(proved.is_err(), "falcon: {}", v.label);
        }
    }
}
