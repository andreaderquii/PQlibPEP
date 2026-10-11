//! RNS-backed leveled homomorphic evaluator used by the BPR12 path.
//!
//! Plaintexts are represented directly in R_17. Ciphertext-ciphertext
//! multiplication performs raw multiplication, relinearization, then one
//! genuine CRT modulus switch (the last RNS prime is dropped). There is no
//! separate Delta rescale in this encoding: the scale-Delta operation from
//! the old single-modulus implementation did not reduce the ciphertext
//! modulus and was not a leveled rescale.

use rand::RngCore;

use crate::algebra::ring::PolyRq;
use crate::core::rlwe_rns::{
    RnsCiphertext,
    RnsKeyGenResult,
    RnsPublicKey,
    RnsRlwe,
    RnsSecretKey,
};
use crate::core::rns::{
    RnsModulusChain,
    RnsPoly,
    RNS_RING_DIMENSION,
};
use crate::core::rns_rlwe_he::{
    RnsRelinearizationKey,
    RnsRlweHe,
};

pub const HE_PLAINTEXT_MODULUS: u64 = 17;

// Twelve ~23-bit RNS primes provide eight complete multiplication/switching
// levels while retaining four primes at the output of level 8. These are
// functional prototype parameters, not a security preset.
const DEFAULT_HE_RNS_MODULI: [u64; 12] = [
    8_416_769,
    8_434_177,
    8_573_441,
    8_599_553,
    8_782_337,
    8_825_857,
    8_834_561,
    8_860_673,
    8_904_193,
    9_113_089,
    9_139_201,
    9_165_313,
];

/// RNS ciphertext plus its level (number of dropped RNS primes).
pub struct HeCiphertext {
    pub ciphertext: RnsCiphertext,
    pub level: usize,
}

impl HeCiphertext {
    pub fn new(ciphertext: RnsCiphertext, level: usize) -> Self {
        Self { ciphertext, level }
    }

    pub fn level(&self) -> usize {
        self.level
    }
}

pub type HePublicKey = RnsPublicKey;
pub type HeSecretKey = RnsSecretKey;
pub type HeKeyGenResult = RnsKeyGenResult;
pub type HeModulusChain = RnsModulusChain;

/// A relinearization key matching each active RNS prefix/level.
pub struct HeRelinearizationKeyChain {
    pub keys: Vec<RnsRelinearizationKey>,
}

/// RNS-backed evaluator for plaintext modulus 17.
pub struct RlweHe {
    engine: RnsRlwe,
    he_engine: RnsRlweHe,
    moduli: Vec<u64>,
    degree: usize,
}

impl RlweHe {
    /// Default 12-prime chain. The default polynomial degree is 256.
    pub fn new() -> Self {
        Self::with_chain(RnsModulusChain::new(
            DEFAULT_HE_RNS_MODULI.to_vec(),
            RNS_RING_DIMENSION,
        ))
    }

    pub fn with_chain(chain: RnsModulusChain) -> Self {
        assert!(
            chain.moduli.len() >= 2,
            "the HE modulus chain needs at least two RNS primes"
        );
        Self {
            engine: RnsRlwe::new(),
            he_engine: RnsRlweHe::new(),
            moduli: chain.moduli,
            degree: chain.degree,
        }
    }

    /// Returns a fresh chain value for the configured full RNS basis.
    pub fn chain(&self) -> HeModulusChain {
        self.chain_for_len(self.moduli.len())
    }

    pub fn max_level(&self) -> usize {
        self.moduli.len() - 1
    }

    pub fn keygen<R: RngCore>(&self, rng: &mut R, n: usize) -> HeKeyGenResult {
        self.assert_degree(n);
        self.engine.keygen(rng, &self.chain())
    }

    pub fn encrypt<R: RngCore>(
        &self,
        rng: &mut R,
        public_key: &HePublicKey,
        plaintext: &PolyRq,
        n: usize,
    ) -> HeCiphertext {
        self.assert_degree(n);
        assert_eq!(plaintext.degree_bound(), n, "plaintext degree mismatch");
        assert_eq!(
            plaintext.modulus(),
            HE_PLAINTEXT_MODULUS,
            "HE plaintext must be in Z_17"
        );
        self.assert_public_key(public_key);

        let message = &plaintext.coefficients()[..n];
        HeCiphertext::new(self.engine.encrypt(rng, public_key, message), 0)
    }

    pub fn decrypt(
        &self,
        secret_key: &HeSecretKey,
        ciphertext: &HeCiphertext,
        n: usize,
    ) -> PolyRq {
        self.assert_degree(n);
        self.assert_ciphertext(ciphertext);
        assert!(
            secret_key.s.residue_count() >= self.active_len(ciphertext.level),
            "secret key does not contain the ciphertext's active RNS basis"
        );

        let active_len = self.active_len(ciphertext.level);
        for i in 0..active_len {
            assert_eq!(
                secret_key.s.residue(i).modulus(),
                self.moduli[i],
                "secret key uses a different modulus at RNS residue {}",
                i
            );
        }
        let level_sk = RnsSecretKey {
            s: RnsPoly {
                residues: secret_key.s.residues[..active_len].to_vec(),
                degree: n,
            },
        };
        let decoded = self.engine.decrypt(&level_sk, &ciphertext.ciphertext);
        PolyRq::from_coeffs(&decoded, n, HE_PLAINTEXT_MODULUS)
    }

    /// Precompute level-matched relinearization keys for each usable prefix.
    pub fn generate_relinearization_key_chain<R: RngCore>(
        &self,
        rng: &mut R,
        secret_key: &HeSecretKey,
        base_bits: usize,
    ) -> HeRelinearizationKeyChain {
        assert_eq!(
            secret_key.s.residue_count(),
            self.moduli.len(),
            "secret key must use the full configured RNS basis"
        );
        assert_eq!(secret_key.s.degree, self.degree);

        let mut keys = Vec::with_capacity(self.max_level());
        for level in 0..self.max_level() {
            let active_len = self.active_len(level);
            let level_chain = self.chain_for_len(active_len);
            let level_sk = RnsSecretKey {
                s: RnsPoly {
                    residues: secret_key.s.residues[..active_len].to_vec(),
                    degree: self.degree,
                },
            };
            // generate_relinearization_key derives the same prefix basis from
            // the reduced secret key, so this key matches the ciphertext level.
            let key = self
                .he_engine
                .generate_relinearization_key(rng, &level_sk, base_bits);
            assert_eq!(level_chain.moduli.len(), active_len);
            keys.push(key);
        }
        HeRelinearizationKeyChain { keys }
    }

    pub fn add_ciphertexts(
        &self,
        lhs: &HeCiphertext,
        rhs: &HeCiphertext,
    ) -> HeCiphertext {
        self.assert_ciphertext(lhs);
        self.assert_ciphertext(rhs);
        assert_eq!(lhs.level, rhs.level, "ciphertexts must be at the same level");
        HeCiphertext::new(
            RnsCiphertext {
                u: lhs.ciphertext.u.add(&rhs.ciphertext.u),
                v: lhs.ciphertext.v.add(&rhs.ciphertext.v),
            },
            lhs.level,
        )
    }

    /// Add an unencrypted R_17 polynomial without consuming a level.
    pub fn add_plaintext(
        &self,
        ciphertext: &HeCiphertext,
        plaintext: &PolyRq,
    ) -> HeCiphertext {
        self.assert_ciphertext(ciphertext);
        let plain_rns = self.plaintext_at_level(plaintext, ciphertext.level);
        HeCiphertext::new(
            RnsCiphertext {
                u: ciphertext.ciphertext.u.clone(),
                v: ciphertext.ciphertext.v.add(&plain_rns),
            },
            ciphertext.level,
        )
    }

    /// Multiply by an unencrypted R_17 polynomial without consuming a level.
    pub fn mul_plaintext(
        &self,
        ciphertext: &HeCiphertext,
        plaintext: &PolyRq,
    ) -> HeCiphertext {
        self.assert_ciphertext(ciphertext);
        let plain_rns = self.plaintext_at_level(plaintext, ciphertext.level);
        HeCiphertext::new(
            RnsCiphertext {
                u: ciphertext.ciphertext.u.mul_negacyclic(&plain_rns),
                v: ciphertext.ciphertext.v.mul_negacyclic(&plain_rns),
            },
            ciphertext.level,
        )
    }

    pub fn negate(&self, ciphertext: &HeCiphertext) -> HeCiphertext {
        self.assert_ciphertext(ciphertext);
        HeCiphertext::new(
            RnsCiphertext {
                u: ciphertext.ciphertext.u.neg(),
                v: ciphertext.ciphertext.v.neg(),
            },
            ciphertext.level,
        )
    }

    pub fn one_minus(
        &self,
        ciphertext: &HeCiphertext,
        one: &PolyRq,
    ) -> HeCiphertext {
        assert_eq!(one.modulus(), HE_PLAINTEXT_MODULUS);
        let negated = self.negate(ciphertext);
        self.add_plaintext(&negated, one)
    }

    /// Multiply ciphertexts, relinearize at the current RNS prefix, then
    /// perform one real modulus switch by removing the final RNS prime.
    /// This is the level transition; there is no separate Delta rescale.
    pub fn mul_ciphertext(
        &self,
        lhs: &HeCiphertext,
        rhs: &HeCiphertext,
        relin_keys: &HeRelinearizationKeyChain,
    ) -> HeCiphertext {
        self.assert_ciphertext(lhs);
        self.assert_ciphertext(rhs);
        assert_eq!(lhs.level, rhs.level, "ciphertexts must be at the same level");
        assert!(lhs.level < self.max_level(), "no modulus-switch level remains");

        let relin_key = relin_keys
            .keys
            .get(lhs.level)
            .expect("missing relinearization key for ciphertext level");
        let product = self.he_engine.mul_raw(&lhs.ciphertext, &rhs.ciphertext);
        let relinearized = self.he_engine.relinearize(&product, relin_key);
        let wrapped = HeCiphertext::new(relinearized, lhs.level);
        self.modulus_switch(&wrapped)
    }

    /// Drop exactly one RNS prime and update the actual ciphertext basis.
    pub fn modulus_switch(&self, ciphertext: &HeCiphertext) -> HeCiphertext {
        self.assert_ciphertext(ciphertext);
        assert!(ciphertext.level < self.max_level(), "cannot switch beyond final level");

        let active_len = self.active_len(ciphertext.level);
        let target_chain = self.chain_for_len(active_len - 1);
        let switched = self
            .he_engine
            .modulus_switch(&ciphertext.ciphertext, &target_chain);
        HeCiphertext::new(switched, ciphertext.level + 1)
    }

    /// Perform as many genuine CRT modulus switches as needed to reach a level.
    pub fn modulus_switch_to_level(
        &self,
        ciphertext: &HeCiphertext,
        target_level: usize,
    ) -> HeCiphertext {
        self.assert_ciphertext(ciphertext);
        assert!(target_level >= ciphertext.level, "cannot switch to a shallower level");
        assert!(target_level <= self.max_level(), "target level is outside the modulus chain");

        let mut current = HeCiphertext::new(
            RnsCiphertext {
                u: ciphertext.ciphertext.u.clone(),
                v: ciphertext.ciphertext.v.clone(),
            },
            ciphertext.level,
        );
        while current.level < target_level {
            current = self.modulus_switch(&current);
        }
        current
    }

    /// Compatibility name retained for BPR12 call sites; this is true RNS
    /// modulus switching, not a metadata-only level update.
    pub fn lift_level(
        &self,
        ciphertext: &HeCiphertext,
        target_level: usize,
    ) -> HeCiphertext {
        self.modulus_switch_to_level(ciphertext, target_level)
    }

    pub fn evaluate_leaf(
        &self,
        encrypted_bit: &HeCiphertext,
        s0: &PolyRq,
        s1: &PolyRq,
    ) -> HeCiphertext {
        self.assert_plaintext(s0);
        self.assert_plaintext(s1);
        assert_eq!(s0.degree_bound(), s1.degree_bound());
        assert_eq!(encrypted_bit.ciphertext.u.degree, s0.degree_bound());

        let difference = s1.sub(s0);
        let selected_difference = self.mul_plaintext(encrypted_bit, &difference);
        self.add_plaintext(&selected_difference, s0)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_2bit_selector(
        &self,
        b0: &HeCiphertext,
        b1: &HeCiphertext,
        s00: &PolyRq,
        s01: &PolyRq,
        s10: &PolyRq,
        s11: &PolyRq,
        relin_keys: &HeRelinearizationKeyChain,
    ) -> HeCiphertext {
        for leaf in [s00, s01, s10, s11] {
            self.assert_plaintext(leaf);
            assert_eq!(leaf.degree_bound(), s00.degree_bound());
        }
        assert_eq!(b0.level, b1.level);
        assert_eq!(b0.ciphertext.u.degree, s00.degree_bound());
        assert_eq!(b1.ciphertext.u.degree, s00.degree_bound());

        let n = s00.degree_bound();
        let mut one_coeffs = vec![0u64; n];
        one_coeffs[0] = 1;
        let one = PolyRq::from_coeffs(&one_coeffs, n, HE_PLAINTEXT_MODULUS);

        let not_b0 = self.one_minus(b0, &one);
        let not_b1 = self.one_minus(b1, &one);
        let t00 = self.mul_ciphertext(&not_b0, &not_b1, relin_keys);
        let t01 = self.mul_ciphertext(&not_b0, b1, relin_keys);
        let t10 = self.mul_ciphertext(b0, &not_b1, relin_keys);
        let t11 = self.mul_ciphertext(b0, b1, relin_keys);

        let term00 = self.mul_plaintext(&t00, s00);
        let term01 = self.mul_plaintext(&t01, s01);
        let term10 = self.mul_plaintext(&t10, s10);
        let term11 = self.mul_plaintext(&t11, s11);
        let sum0 = self.add_ciphertexts(&term00, &term01);
        let sum1 = self.add_ciphertexts(&term10, &term11);
        self.add_ciphertexts(&sum0, &sum1)
    }

    pub fn select_ciphertexts(
        &self,
        encrypted_bit: &HeCiphertext,
        left: &HeCiphertext,
        right: &HeCiphertext,
        relin_keys: &HeRelinearizationKeyChain,
    ) -> HeCiphertext {
        assert_eq!(left.level, right.level);
        let bit = self.modulus_switch_to_level(encrypted_bit, left.level);
        let neg_left = self.negate(left);
        let difference = self.add_ciphertexts(right, &neg_left);
        let selected_difference = self.mul_ciphertext(&bit, &difference, relin_keys);
        let left_aligned = self.modulus_switch_to_level(left, selected_difference.level);
        self.add_ciphertexts(&left_aligned, &selected_difference)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_3bit_selector(
        &self,
        b0: &HeCiphertext,
        b1: &HeCiphertext,
        b2: &HeCiphertext,
        s000: &PolyRq,
        s001: &PolyRq,
        s010: &PolyRq,
        s011: &PolyRq,
        s100: &PolyRq,
        s101: &PolyRq,
        s110: &PolyRq,
        s111: &PolyRq,
        relin_keys: &HeRelinearizationKeyChain,
    ) -> HeCiphertext {
        let node00 = self.evaluate_leaf(b2, s000, s001);
        let node01 = self.evaluate_leaf(b2, s010, s011);
        let node10 = self.evaluate_leaf(b2, s100, s101);
        let node11 = self.evaluate_leaf(b2, s110, s111);
        let node0 = self.select_ciphertexts(b1, &node00, &node01, relin_keys);
        let node1 = self.select_ciphertexts(b1, &node10, &node11, relin_keys);
        self.select_ciphertexts(b0, &node0, &node1, relin_keys)
    }

    pub fn evaluate_oblivious_tree(
        &self,
        bits: &[HeCiphertext],
        leaves: &[PolyRq],
        relin_keys: &HeRelinearizationKeyChain,
    ) -> HeCiphertext {
        assert!(!bits.is_empty(), "at least one selector bit is required");
        let expected_leaves = 1usize
            .checked_shl(bits.len() as u32)
            .expect("too many selector bits");
        assert_eq!(leaves.len(), expected_leaves);
        for leaf in leaves {
            self.assert_plaintext(leaf);
        }

        let mut nodes = leaves
            .chunks_exact(2)
            .map(|pair| self.evaluate_leaf(&bits[bits.len() - 1], &pair[0], &pair[1]))
            .collect::<Vec<_>>();
        for bit_index in (0..bits.len() - 1).rev() {
            let mut next_nodes = Vec::with_capacity(nodes.len() / 2);
            for pair in nodes.chunks_exact(2) {
                next_nodes.push(self.select_ciphertexts(
                    &bits[bit_index],
                    &pair[0],
                    &pair[1],
                    relin_keys,
                ));
            }
            nodes = next_nodes;
        }
        assert_eq!(nodes.len(), 1);
        nodes.remove(0)
    }

    fn assert_degree(&self, n: usize) {
        assert_eq!(n, self.degree, "polynomial degree does not match HE chain");
    }

    fn assert_plaintext(&self, plaintext: &PolyRq) {
        assert_eq!(plaintext.modulus(), HE_PLAINTEXT_MODULUS, "plaintext must be in Z_17");
        assert_eq!(plaintext.degree_bound(), self.degree, "plaintext degree mismatch");
    }

    fn active_len(&self, level: usize) -> usize {
        assert!(level <= self.max_level(), "ciphertext level outside RNS chain");
        self.moduli.len() - level
    }

    fn chain_for_len(&self, active_len: usize) -> RnsModulusChain {
        assert!(active_len > 0 && active_len <= self.moduli.len());
        RnsModulusChain::new(self.moduli[..active_len].to_vec(), self.degree)
    }

    fn assert_ciphertext(&self, ciphertext: &HeCiphertext) {
        let active_len = self.active_len(ciphertext.level);
        assert_eq!(ciphertext.ciphertext.u.degree, self.degree);
        assert_eq!(ciphertext.ciphertext.v.degree, self.degree);
        assert_eq!(ciphertext.ciphertext.u.residue_count(), active_len);
        assert_eq!(ciphertext.ciphertext.v.residue_count(), active_len);
        for i in 0..active_len {
            assert_eq!(ciphertext.ciphertext.u.residue(i).modulus(), self.moduli[i]);
            assert_eq!(ciphertext.ciphertext.v.residue(i).modulus(), self.moduli[i]);
        }
    }

    fn assert_public_key(&self, public_key: &HePublicKey) {
        assert_eq!(public_key.a.degree, self.degree);
        assert_eq!(public_key.b.degree, self.degree);
        assert_eq!(public_key.a.residue_count(), self.moduli.len());
        assert_eq!(public_key.b.residue_count(), self.moduli.len());
        for i in 0..self.moduli.len() {
            assert_eq!(public_key.a.residue(i).modulus(), self.moduli[i]);
            assert_eq!(public_key.b.residue(i).modulus(), self.moduli[i]);
        }
    }

    fn plaintext_at_level(&self, plaintext: &PolyRq, level: usize) -> RnsPoly {
        self.assert_plaintext(plaintext);
        let active_len = self.active_len(level);
        RnsPoly::from_coeffs(
            &plaintext.coefficients()[..self.degree],
            &self.chain_for_len(active_len),
        )
    }
}

impl Default for RlweHe {
    fn default() -> Self {
        Self::new()
    }
}
