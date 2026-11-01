//  Copyright 2024. The Tari Project
//
//  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
//  following conditions are met:
//
//  1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
//  disclaimer.
//
//  2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
//  following disclaimer in the documentation and/or other materials provided with the distribution.
//
//  3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
//  products derived from this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
//  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
//  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
//  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

mod error;
mod mnemonics;
pub mod network;

use base58_monero::base58;
use crc::{
    crc32::{Digest as CrcDigest, IEEE},
    Hasher32,
};
use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};
use error::Error;
use mnemonics::{find_word_index, ENGLISH};
use network::Network;
use rand::{rngs::OsRng, RngCore};
use sha3::{Digest, Keccak256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seed {
    inner: [u8; 32],
}

const SEED_WORD_COUNT: usize = 24;
const SEED_WORD_COUNT_WITH_CHECKSUM: usize = 25;
const TRIM_LENGTH: usize = 3;

#[derive(Debug)]
struct PrivateKey([u8; 32]);
type PublicKey = [u8; 32];

impl PrivateKey {
    pub fn inner(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_public_key(&self) -> PublicKey {
        let private = &Scalar::from_bytes_mod_order(*self.inner());
        let public = private * ED25519_BASEPOINT_TABLE;

        *public.compress().as_bytes()
    }
}

impl Seed {
    pub fn new(inner: [u8; 32]) -> Self {
        Self { inner }
    }

    pub fn inner(&self) -> &[u8; 32] {
        &self.inner
    }

    pub fn generate() -> Result<Seed, Error> {
        let entropy = generate_entropy();
        let inner = Scalar::from_bytes_mod_order(entropy).to_bytes();
        let seed = Self::new(inner);
        let words = seed.seed_words()?;
        Self::from_seed_words(&words)
    }

    pub fn from_seed_words(seed_words: &[String]) -> Result<Self, Error> {
        if seed_words.len() != SEED_WORD_COUNT_WITH_CHECKSUM {
            return Err(Error::NotEnoughSeedWords);
        }

        let length = ENGLISH.len();
        let trimmed_words_list = ENGLISH
            .iter()
            .map(|w| w.chars().take(TRIM_LENGTH).collect())
            .collect::<Vec<String>>();

        let mut normalized_words = seed_words
            .iter()
            .map(|w| w.trim().to_ascii_lowercase())
            .collect::<Vec<String>>();
        let checksum_word = normalized_words.pop().ok_or(Error::NotEnoughSeedWords)?;
        let checksum_prefix = checksum_word.chars().take(TRIM_LENGTH).collect::<String>();
        let _checksum_word_idx = find_word_index(&trimmed_words_list, &checksum_prefix)?;

        let mut buffer = Vec::with_capacity(32);
        let mut trimmed_seed_words = Vec::with_capacity(SEED_WORD_COUNT);
        for chunk in normalized_words.chunks(3) {
            let p1 = chunk[0].chars().take(TRIM_LENGTH).collect::<String>();
            let p2 = chunk[1].chars().take(TRIM_LENGTH).collect::<String>();
            let p3 = chunk[2].chars().take(TRIM_LENGTH).collect::<String>();

            let w1 = find_word_index(&trimmed_words_list, &p1)?;
            let w2 = find_word_index(&trimmed_words_list, &p2)?;
            let w3 = find_word_index(&trimmed_words_list, &p3)?;

            trimmed_seed_words.push(p1);
            trimmed_seed_words.push(p2);
            trimmed_seed_words.push(p3);

            let n = length;
            let x = w1 + n * (((n - w1) + w2) % n) + n * n * (((n - w2) + w3) % n);

            buffer.extend_from_slice(&u32::to_le_bytes(u32::try_from(x)?));
        }

        let expected_checksum_idx = compute_checksum_index(&trimmed_seed_words);
        if checksum_prefix != trimmed_seed_words[expected_checksum_idx] {
            return Err(Error::InvalidSeedWords);
        }

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&buffer);

        Ok(Self { inner: seed })
    }

    fn private_spend_key(&self) -> PrivateKey {
        PrivateKey(Scalar::from_bytes_mod_order(self.inner).to_bytes())
    }

    fn private_view_key(&self) -> PrivateKey {
        PrivateKey(Scalar::from_bytes_mod_order(keccak256(&self.private_spend_key().0)).to_bytes())
    }

    pub fn seed_words(&self) -> Result<Vec<String>, Error> {
        let seed = &Scalar::from_bytes_mod_order(self.inner).to_bytes();

        // Reverse the endian in 4 byte intervals
        let length = u32::try_from(ENGLISH.len())?;
        let inputs = seed
            .chunks(4)
            .map(|chunk| {
                let mut input: [u8; 4] = [0u8; 4];
                input.copy_from_slice(chunk);

                u32::from_le_bytes(input)
            })
            .collect::<Vec<u32>>();

        // Generate three words from every 4 byte interval
        let mut seed_words = Vec::with_capacity(SEED_WORD_COUNT_WITH_CHECKSUM);
        for index in inputs {
            let w1 = index % length;
            let w2 = ((index / length) + w1) % length;
            let w3 = (((index / length) / length) + w2) % length;

            seed_words.push(ENGLISH[w1 as usize].to_string());
            seed_words.push(ENGLISH[w2 as usize].to_string());
            seed_words.push(ENGLISH[w3 as usize].to_string());
        }

        if seed_words.len() != SEED_WORD_COUNT {
            return Err(Error::DidntGenerateEnoughWords);
        }

        let trimmed_seed_words = seed_words
            .iter()
            .map(|w| w.chars().take(TRIM_LENGTH).collect())
            .collect::<Vec<String>>();

        let checksum_idx = compute_checksum_index(&trimmed_seed_words);
        let last_word = seed_words[checksum_idx].clone();
        seed_words.push(last_word);

        Ok(seed_words)
    }

    pub fn to_address<N: Network>(&self) -> Result<String, Error> {
        let mut bytes = vec![N::network_byte()];
        bytes.extend_from_slice(&self.private_spend_key().to_public_key());
        bytes.extend_from_slice(&self.private_view_key().to_public_key());

        let checksum_bytes = &bytes[0..65];
        let checksum = &keccak256(checksum_bytes);
        bytes.extend_from_slice(&checksum[0..4]);

        base58::encode(bytes.as_slice()).map_err(|e| Error::BadEncoding(e.to_string()))
    }
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result[..]);
    hash
}

fn generate_entropy() -> [u8; 32] {
    let mut entropy = [0u8; 32];
    let mut rng = OsRng;
    rng.fill_bytes(&mut entropy);
    entropy
}

fn compute_checksum_index(trimmed_seed_words: &[String]) -> usize {
    let mut digest = CrcDigest::new(IEEE);
    digest.write(trimmed_seed_words.concat().as_bytes());
    (digest.sum32() as usize) % trimmed_seed_words.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{Mainnet, Stagenet};

    #[test]
    fn generates_correct_mainnet_address_from_seeds() {
        #[rustfmt::skip]
        let seed_words = [
            "razor", "obnoxious", "entrance", "inroads", "saxophone", "among", "onward", "revamp",
            "scoop", "boxes", "point", "fawns", "rigid", "army", "badge", "icing", "frying",
            "voted", "biggest", "layout", "dehydrate", "acidic", "reinvest", "school", "inroads",
        ];
        let seed_words = seed_words.iter().map(|w| w.to_string()).collect::<Vec<String>>();

        let expected_address =
            "45Q1XvrXszmdK23braS6YZEJA3Ei6LoJNJ7J4GJqmSbFJXGowyxgj2V4yLh6vTeNv2c7EPov94bUZ22JupjH591hLAmYT5M";

        let seed = Seed::from_seed_words(&seed_words).unwrap();
        let address = seed.to_address::<Mainnet>().unwrap();

        assert_eq!(address, expected_address);
    }

    #[test]
    fn generates_correct_stagenet_address_from_seeds() {
        #[rustfmt::skip]
        let seed_words = [
            "dauntless", "unwind", "gourmet", "timber", "fugitive", "request", "gourmet", "devoid",
            "mechanic", "snug", "ornament", "equip", "puck", "puck", "water", "nugget", "maze",
            "dude", "arises", "hectare", "smog", "solved", "dummy", "enmity", "ornament"
        ];
        let seed_words = seed_words.iter().map(|w| w.to_string()).collect::<Vec<String>>();

        let expected_address =
            "56xCt2ZKdPE7Qfgjb4puy3FZYtsEaj2Ky6fHxFFUMe5TRiVD7BzAZcQXeNfju3tocjVChbjhWussg5R3Jr88EwamA4u9V6f";

        let seed = Seed::from_seed_words(&seed_words).unwrap();
        let address = seed.to_address::<Stagenet>().unwrap();

        assert_eq!(address, expected_address);
    }

    #[test]
    fn generates_new_seeds_with_address() {
        let seed = Seed::generate().unwrap();
        let address = seed.to_address::<Stagenet>().unwrap();

        let new_seed = Seed::from_seed_words(&seed.seed_words().unwrap()).unwrap();
        let new_address = new_seed.to_address::<Stagenet>().unwrap();

        assert_eq!(address, new_address);
    }

    #[test]
    fn can_recreate_seed_words_from_seed() {
        #[rustfmt::skip]
        let seed_words = [
            "dauntless", "unwind", "gourmet", "timber", "fugitive", "request", "gourmet", "devoid",
            "mechanic", "snug", "ornament", "equip", "puck", "puck", "water", "nugget", "maze",
            "dude", "arises", "hectare", "smog", "solved", "dummy", "enmity", "ornament"
        ];
        let seed_words = seed_words.iter().map(|w| w.to_string()).collect::<Vec<String>>();

        let seed = Seed::from_seed_words(&seed_words).unwrap();
        assert_eq!(seed_words, seed.seed_words().unwrap());
    }

    #[test]
    fn generates_same_seeds() {
        let seed1 = Seed::generate().unwrap();
        let words1 = seed1.seed_words().unwrap();

        let seed2 = Seed::from_seed_words(&words1).unwrap();
        let words2 = seed2.seed_words().unwrap();

        assert_eq!(words1, words2);
        assert_eq!(
            seed1.to_address::<Stagenet>().unwrap(),
            seed2.to_address::<Stagenet>().unwrap()
        );
    }

    #[test]
    fn rejects_invalid_checksum_word() {
        #[rustfmt::skip]
        let mut seed_words = [
            "razor", "obnoxious", "entrance", "inroads", "saxophone", "among", "onward", "revamp",
            "scoop", "boxes", "point", "fawns", "rigid", "army", "badge", "icing", "frying",
            "voted", "biggest", "layout", "dehydrate", "acidic", "reinvest", "school", "inroads",
        ]
        .iter()
        .map(|w| w.to_string())
        .collect::<Vec<String>>();

        seed_words[24] = "razor".to_string();
        assert_eq!(Seed::from_seed_words(&seed_words), Err(Error::InvalidSeedWords));
    }

    #[test]
    fn rejects_unknown_checksum_word() {
        #[rustfmt::skip]
        let mut seed_words = [
            "razor", "obnoxious", "entrance", "inroads", "saxophone", "among", "onward", "revamp",
            "scoop", "boxes", "point", "fawns", "rigid", "army", "badge", "icing", "frying",
            "voted", "biggest", "layout", "dehydrate", "acidic", "reinvest", "school", "inroads",
        ]
        .iter()
        .map(|w| w.to_string())
        .collect::<Vec<String>>();

        seed_words[24] = "zzzzzz".to_string();
        assert_eq!(Seed::from_seed_words(&seed_words), Err(Error::WordNotFound));
    }

    #[test]
    fn rejects_wrong_seed_word_count() {
        let too_few = vec!["abbey".to_string(); 24];
        let too_many = vec!["abbey".to_string(); 26];
        assert_eq!(Seed::from_seed_words(&too_few), Err(Error::NotEnoughSeedWords));
        assert_eq!(Seed::from_seed_words(&too_many), Err(Error::NotEnoughSeedWords));
    }

    #[test]
    fn normalizes_case_and_whitespace_in_seed_words() {
        #[rustfmt::skip]
        let seed_words = [
            "  RAZOR ", "Obnoxious", "ENTRANCE", "inroads", "saxophone", "among", "onward", "revamp",
            "scoop", "boxes", "point", "fawns", "rigid", "army", "badge", "icing", "frying",
            "voted", "biggest", "layout", "dehydrate", "acidic", "reinvest", "school", " INROADS\n",
        ]
        .iter()
        .map(|w| w.to_string())
        .collect::<Vec<String>>();

        let expected_address =
            "45Q1XvrXszmdK23braS6YZEJA3Ei6LoJNJ7J4GJqmSbFJXGowyxgj2V4yLh6vTeNv2c7EPov94bUZ22JupjH591hLAmYT5M";
        let seed = Seed::from_seed_words(&seed_words).unwrap();
        assert_eq!(seed.to_address::<Mainnet>().unwrap(), expected_address);
    }

    #[test]
    fn generate_produces_canonical_round_tripping_seeds() {
        for _ in 0..256 {
            let seed1 = Seed::generate().unwrap();
            let words1 = seed1.seed_words().unwrap();
            let seed2 = Seed::from_seed_words(&words1).unwrap();
            let words2 = seed2.seed_words().unwrap();
            assert_eq!(seed1, seed2);
            assert_eq!(words1, words2);
        }
    }
}
