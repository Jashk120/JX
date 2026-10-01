//! SLIP-0010 `ed25519` hardened-only hierarchical deterministic key derivation.
//!
//! Library-side only: the seed and every derived private key stay off-chain and
//! must never enter consensus state. [`did_control_key`] derives the canonical
//! DID-control path `m/19019'/0'/generation'`; [`actor_control_key`] derives the
//! canonical actor-control path `m/19019'/1'/tag_code'/index'`.

use ed25519_dalek::SigningKey;
use hmac::Mac;

use crate::error::{
    CryptoError,
    Result,
};

/// Offset added to a path element to form the hardened child index.
///
/// Callers pass non-hardened elements (`< 0x8000_0000`); every level derived
/// here is hardened, as SLIP-0010 requires for `ed25519`.
const HARDENED_OFFSET: u32 = 0x8000_0000;

/// Highest valid actor tag code (`0 = defi, 1 = messenger, 2 = game, 3 = generic`).
const MAX_TAG_CODE: u8 = 3;

/// SLIP-0010 purpose value assigned to JKain actor keys.
const PURPOSE: u32 = 19_019;

/// HMAC-SHA512 with the given key over the given data.
fn hmac_sha512(key: &[u8], data: &[u8]) -> Result<[u8; 64]> {
    let mut mac =
        hmac::Hmac::<sha2::Sha512>::new_from_slice(key).map_err(|_| CryptoError::HmacInitFailed)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().into())
}

/// SLIP-0010 `ed25519` master key and chain code from a seed.
///
/// `I = HMAC-SHA512(key = b"ed25519 seed", data = seed)`, split into
/// `key = I[0..32]` and `chain_code = I[32..64]`.
fn master_key(seed: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    let output = hmac_sha512(b"ed25519 seed", seed)?;
    let mut key = [0_u8; 32];
    let mut chain_code = [0_u8; 32];
    key.copy_from_slice(&output[..32]);
    chain_code.copy_from_slice(&output[32..]);
    Ok((key, chain_code))
}

/// SLIP-0010 `ed25519` hardened child of `(key_par, chain_par)` at `index`.
///
/// `I = HMAC-SHA512(key = chain_par, data = 0x00 || key_par || ser32(index +
/// 0x8000_0000))`, split into `key = I[0..32]` and `chain_code = I[32..64]`.
/// `index` must be the non-hardened element (`< 0x8000_0000`), so the addition
/// cannot overflow.
fn child_key(key_par: &[u8; 32], chain_par: &[u8; 32], index: u32) -> Result<([u8; 32], [u8; 32])> {
    let hardened = index + HARDENED_OFFSET;
    let mut data = [0_u8; 1 + 32 + 4];
    data[0] = 0x00;
    data[1..33].copy_from_slice(key_par);
    data[33..37].copy_from_slice(&hardened.to_be_bytes());
    let output = hmac_sha512(chain_par, &data)?;
    let mut key = [0_u8; 32];
    let mut chain_code = [0_u8; 32];
    key.copy_from_slice(&output[..32]);
    chain_code.copy_from_slice(&output[32..]);
    Ok((key, chain_code))
}

/// Derives an `ed25519` signing key from `seed` along a fully hardened path.
///
/// Every element of `path` is treated as a non-hardened index and hardened
/// internally (`child = element + 0x8000_0000`); elements `>= 0x8000_0000`
/// are rejected, as is an empty path. Implements SLIP-0010 for `ed25519`
/// exactly: only private-parent to private-child (hardened) derivation.
///
/// # Errors
///
/// Returns `EmptyDerivationPath` when `path` is empty and
/// `InvalidDerivationIndex` when an element is already hardened.
pub fn derive_ed25519(seed: &[u8], path: &[u32]) -> Result<SigningKey> {
    if path.is_empty() {
        return Err(CryptoError::EmptyDerivationPath);
    }
    let (mut key, mut chain_code) = master_key(seed)?;
    for element in path {
        if *element >= HARDENED_OFFSET {
            return Err(CryptoError::InvalidDerivationIndex(*element));
        }
        (key, chain_code) = child_key(&key, &chain_code, *element)?;
    }
    Ok(SigningKey::from_bytes(&key))
}

/// Derives the DID-control key for `generation` from `seed`.
///
/// Canonical path `m/19019'/0'/generation'`. Library-side only: private
/// material derived here must never enter consensus state.
///
/// # Errors
///
/// Returns `InvalidDerivationIndex` when `generation` is already hardened.
pub fn did_control_key(seed: &[u8], generation: u32) -> Result<SigningKey> {
    if generation >= HARDENED_OFFSET {
        return Err(CryptoError::InvalidDerivationIndex(generation));
    }
    derive_ed25519(seed, &[PURPOSE, 0, generation])
}

/// Derives the actor-control key for `tag_code` and `index` from `seed`.
///
/// Canonical path `m/19019'/1'/tag_code'/index'`, where `tag_code` is
/// `0 = defi, 1 = messenger, 2 = game, 3 = generic`. Library-side only:
/// private material derived here must never enter consensus state.
///
/// # Errors
///
/// Returns `InvalidTagCode` when `tag_code > 3` and `InvalidDerivationIndex`
/// when `index` is already hardened.
pub fn actor_control_key(seed: &[u8], tag_code: u8, index: u32) -> Result<SigningKey> {
    if tag_code > MAX_TAG_CODE {
        return Err(CryptoError::InvalidTagCode(tag_code));
    }
    if index >= HARDENED_OFFSET {
        return Err(CryptoError::InvalidDerivationIndex(index));
    }
    derive_ed25519(seed, &[PURPOSE, 1, u32::from(tag_code), index])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex(hex: &str) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(hex.len() / 2);
        let digits = hex.as_bytes();
        let mut index = 0;
        while index < digits.len() {
            let high = hex_value(digits[index]) << 4;
            let low = hex_value(digits[index + 1]);
            bytes.push(high | low);
            index += 2;
        }
        bytes
    }

    fn hex_value(digit: u8) -> u8 {
        match digit {
            b'0'..=b'9' => digit - b'0',
            b'a'..=b'f' => digit - b'a' + 10,
            b'A'..=b'F' => digit - b'A' + 10,
            _ => 0,
        }
    }

    fn encode_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }

    fn signing_hex(key: &SigningKey) -> String {
        encode_hex(key.as_bytes())
    }

    fn verifying_hex(key: &SigningKey) -> String {
        encode_hex(key.verifying_key().as_bytes())
    }

    /// Official SLIP-0010 `ed25519` test vector 1 (seed `000102...0f`).
    ///
    /// The spec chains are `m`, `m/0H`, `m/0H/1H`, `m/0H/1H/2H`,
    /// `m/0H/1H/2H/2H`, `m/0H/1H/2H/2H/1000000000H`; the public keys below
    /// are the spec values with the leading `0x00` byte stripped.
    #[test]
    fn slip10_ed25519_vector1() {
        let seed = decode_hex("000102030405060708090a0b0c0d0e0f");
        let cases: &[(&[u32], &str, &str)] = &[
            (
                &[0],
                "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
                "8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c",
            ),
            (
                &[0, 1],
                "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
                "1932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187",
            ),
            (
                &[0, 1, 2],
                "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
                "ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1",
            ),
            (
                &[0, 1, 2, 2],
                "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
                "8abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c",
            ),
            (
                &[0, 1, 2, 2, 1_000_000_000],
                "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
                "3c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a",
            ),
        ];
        for (path, private_hex, public_hex) in cases {
            let key = derive_ed25519(&seed, path).unwrap();
            assert_eq!(signing_hex(&key), *private_hex, "path {path:?}");
            assert_eq!(verifying_hex(&key), *public_hex, "path {path:?}");
        }
    }

    /// Official SLIP-0010 `ed25519` test vector 2 (64-byte seed).
    #[test]
    fn slip10_ed25519_vector2() {
        let seed = decode_hex(
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784\
             817e7b7875726f6c696663605d5a5754514e4b484542",
        );
        let cases: &[(&[u32], &str, &str)] = &[
            (
                &[0],
                "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635",
                "86fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037",
            ),
            (
                &[0, 2_147_483_647],
                "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4",
                "5ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d",
            ),
            (
                &[0, 2_147_483_647, 1],
                "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c",
                "2e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45",
            ),
            (
                &[0, 2_147_483_647, 1, 2_147_483_646],
                "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72",
                "e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b",
            ),
            (
                &[0, 2_147_483_647, 1, 2_147_483_646, 2],
                "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d",
                "47150c75db263559a70d5778bf36abbab30fb061ad69f69ece61a72b0cfa4fc0",
            ),
        ];
        for (path, private_hex, public_hex) in cases {
            let key = derive_ed25519(&seed, path).unwrap();
            assert_eq!(signing_hex(&key), *private_hex, "path {path:?}");
            assert_eq!(verifying_hex(&key), *public_hex, "path {path:?}");
        }
    }

    #[test]
    fn rejects_empty_path() {
        let seed = decode_hex("000102030405060708090a0b0c0d0e0f");
        assert_eq!(derive_ed25519(&seed, &[]), Err(CryptoError::EmptyDerivationPath));
    }

    #[test]
    fn rejects_hardened_path_element() {
        let seed = decode_hex("000102030405060708090a0b0c0d0e0f");
        assert_eq!(
            derive_ed25519(&seed, &[0x8000_0000]),
            Err(CryptoError::InvalidDerivationIndex(0x8000_0000))
        );
        assert_eq!(
            derive_ed25519(&seed, &[0, u32::MAX]),
            Err(CryptoError::InvalidDerivationIndex(u32::MAX))
        );
    }

    #[test]
    fn rejects_bad_generation_and_tag() {
        let seed = decode_hex("000102030405060708090a0b0c0d0e0f");
        assert_eq!(
            did_control_key(&seed, 0x8000_0000),
            Err(CryptoError::InvalidDerivationIndex(0x8000_0000))
        );
        assert_eq!(actor_control_key(&seed, 4, 0), Err(CryptoError::InvalidTagCode(4)));
        assert_eq!(
            actor_control_key(&seed, 0, 0x8000_0000),
            Err(CryptoError::InvalidDerivationIndex(0x8000_0000))
        );
    }

    #[test]
    fn canonical_paths_match_explicit_derivation() {
        let seed = decode_hex("000102030405060708090a0b0c0d0e0f");
        let did = did_control_key(&seed, 7).unwrap();
        let explicit = derive_ed25519(&seed, &[19_019, 0, 7]).unwrap();
        assert_eq!(did.as_bytes(), explicit.as_bytes());
        let actor = actor_control_key(&seed, 2, 9).unwrap();
        let explicit = derive_ed25519(&seed, &[19_019, 1, 2, 9]).unwrap();
        assert_eq!(actor.as_bytes(), explicit.as_bytes());
    }

    /// Canonical-path regression vectors (`m/19019'/...`).
    ///
    /// These paths are JKain-specific (PLAN-5 D-5) and have no SLIP-0010 spec
    /// counterpart: the values below were generated with this implementation
    /// after it was validated against the official SLIP-0010 vectors above,
    /// using the fixed 32-byte seed `000102...1f`. They lock the canonical
    /// paths against accidental changes to the derivation code.
    #[test]
    fn canonical_path_regression_vectors() {
        let seed = decode_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let cases: &[(SigningKey, &str, &str)] = &[
            (
                // m/19019'/0'/0'
                did_control_key(&seed, 0).unwrap(),
                "f8c917f45cf713dfebd3e764e749e1589043bd0f3f8db7f1b6b0472852ea6b9a",
                "df5730b36f2f496f5553c25bc989ee103cb07142fe1f022d9e3a58fb7ca15e36",
            ),
            (
                // m/19019'/0'/1'
                did_control_key(&seed, 1).unwrap(),
                "7125f5c55561a725c798271da68964e2f06f42b2428a1c1f4dae2beeae667f74",
                "99e548d60e59554147a7f11d494a3c0856d6c2d610b3f5ee04a0d4f706562122",
            ),
            (
                // m/19019'/1'/0'/0'
                actor_control_key(&seed, 0, 0).unwrap(),
                "ce00174f93374277c70b1d31ce2e1430461697bc3db187631d3c4ebb60dc2ce6",
                "afac5cd123e400e5a6d6423c71be31577640cc9a4c203d83c6350e50708a4a19",
            ),
            (
                // m/19019'/1'/3'/42'
                actor_control_key(&seed, 3, 42).unwrap(),
                "29de6836b730a33dfe8c72a35bff815fc82021a8377b5520532c98a7f403a69c",
                "2770c178ca21d971a809c9f4a0d42df0c8854586b008ccb720fabc1e5f151cd3",
            ),
        ];
        assert_eq!(cases.len(), 4);
        for (key, private_hex, public_hex) in cases {
            assert_eq!(signing_hex(key), *private_hex);
            assert_eq!(verifying_hex(key), *public_hex);
        }
    }
}
