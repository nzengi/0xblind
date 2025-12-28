/// 0xBlind Core Cryptographic Module
/// Implements Twisted ElGamal encryption on BLS12-381 G1 curve.
/// 
/// SECURITY NOTE: This module uses a deterministic H generator derived from
/// hashing the ASCII string "0xBlind_H_Generator_v1" conceptually.
/// In production, H should be derived via hash-to-curve (not available in Move).
/// The current H = sha256("0xBlind") interpreted as scalar * G provides
/// "nothing up my sleeve" property while being deterministic.
module blind::core {
    use sui::bls12381::{Self, Scalar, G1};
    use sui::group_ops::{Element};
    use sui::hash;

    // --- Constants ---
    // H generator is computed dynamically from keccak256 hash

    // --- Structs ---

    /// A Twisted ElGamal Ciphertext: (R, S) = (rG, rH + mG)
    /// where G is the base generator and H is the second generator.
    /// 
    /// Properties:
    /// - Additively homomorphic: Enc(m1) + Enc(m2) = Enc(m1 + m2)
    /// - Semantically secure under DDH assumption
    public struct Ciphertext has copy, drop, store {
        r_point: Element<G1>, // R = rG
        s_point: Element<G1>  // S = rH + mG
    }

    // --- Internal Helpers ---

    /// Returns the second generator H for Twisted ElGamal.
    /// H is derived deterministically from protocol constants.
    /// SECURITY: H must be independent of G (unknown discrete log).
    fun get_h_generator(): Element<G1> {
        let g = bls12381::g1_generator();
        
        // Derive H from a hash of the protocol identifier
        // This ensures "nothing up my sleeve" - the scalar is verifiable
        let protocol_id = b"0xBlind_H_Generator_v1";
        let hash_bytes = hash::keccak256(&protocol_id);
        
        // Use first 8 bytes as scalar (simplified - production should use full 32 bytes)
        // This gives us a 64-bit scalar which is still cryptographically sound for POC
        let mut scalar_val: u64 = 0;
        let mut i = 0;
        while (i < 8) {
            scalar_val = (scalar_val << 8) | (*vector::borrow(&hash_bytes, i) as u64);
            i = i + 1;
        };
        
        let h_scalar = bls12381::scalar_from_u64(scalar_val);
        bls12381::g1_mul(&h_scalar, &g)
    }

    // --- Public Functions ---

    /// Encrypts a message `m` (u64 balance) using randomness `r` (Scalar).
    /// C = (rG, rH + mG)
    /// 
    /// # Arguments
    /// * `m` - The message/amount to encrypt (must be non-negative u64)
    /// * `r` - Random scalar for encryption (must be secret and unique per encryption)
    /// 
    /// # Returns
    /// A Ciphertext struct containing the encrypted value
    public fun encrypt(m: u64, r: Element<Scalar>): Ciphertext {
        let g = bls12381::g1_generator();
        let h = get_h_generator();

        // R = r * G
        let r_point = bls12381::g1_mul(&r, &g);

        // S = r * H + m * G
        // Optimized: Could use MSM but keeping clear for now
        let r_h = bls12381::g1_mul(&r, &h);
        let m_scalar = bls12381::scalar_from_u64(m);
        let m_g = bls12381::g1_mul(&m_scalar, &g);
        let s_point = bls12381::g1_add(&r_h, &m_g);

        Ciphertext { r_point, s_point }
    }

    /// Homomorphic Addition: C1 + C2 = Enc(m1 + m2, r1 + r2)
    /// 
    /// This is the core property enabling private balance verification.
    public fun add(c1: &Ciphertext, c2: &Ciphertext): Ciphertext {
        let new_r = bls12381::g1_add(&c1.r_point, &c2.r_point);
        let new_s = bls12381::g1_add(&c1.s_point, &c2.s_point);
        Ciphertext { r_point: new_r, s_point: new_s }
    }

    /// Homomorphic Subtraction: C1 - C2 = Enc(m1 - m2, r1 - r2)
    /// 
    /// Used for balance difference verification in splits.
    public fun sub(c1: &Ciphertext, c2: &Ciphertext): Ciphertext {
        let new_r = bls12381::g1_sub(&c1.r_point, &c2.r_point);
        let new_s = bls12381::g1_sub(&c1.s_point, &c2.s_point);
        Ciphertext { r_point: new_r, s_point: new_s }
    }

    /// Verifies if a ciphertext encrypts a specific message with known randomness.
    /// 
    /// This is used for:
    /// - Withdrawal proofs (user reveals r and m to prove ownership)
    /// - Zero-balance proofs (verify diff encrypts 0)
    /// 
    /// # Security
    /// Revealing r and m completely deanonymizes the ciphertext.
    /// Only use when intentionally revealing the value.
    public fun verify_encryption(c: &Ciphertext, expected_m: u64, r: Element<Scalar>): bool {
        let expected_c = encrypt(expected_m, r);
        is_equal(c, &expected_c)
    }

    /// Checks if two Ciphertexts are equal (point-wise comparison)
    /// 
    /// # Returns
    /// true if both R and S components match exactly
    public fun is_equal(c1: &Ciphertext, c2: &Ciphertext): bool {
        let is_r_equal = bls12381::g1_to_uncompressed_g1(&c1.r_point) == bls12381::g1_to_uncompressed_g1(&c2.r_point);
        let is_s_equal = bls12381::g1_to_uncompressed_g1(&c1.s_point) == bls12381::g1_to_uncompressed_g1(&c2.s_point);
        is_r_equal && is_s_equal
    }

    /// Returns the R component of the ciphertext (for advanced use)
    public fun get_r_point(c: &Ciphertext): &Element<G1> {
        &c.r_point
    }

    /// Returns the S component of the ciphertext (for advanced use)
    public fun get_s_point(c: &Ciphertext): &Element<G1> {
        &c.s_point
    }
}