/// 0xBlind Proof Verification Module
/// Implements secure verification for private transfers with inflation protection.
/// 
/// All verification requires explicit amount reveals to prevent negative balance attacks.
module blind::proof {
    use blind::core::{Self, Ciphertext};
    use sui::bls12381::Scalar;
    use sui::group_ops::Element;

    // --- Error Codes ---
    const EZeroBalanceCheckFailed: u64 = 1;
    const EInputProofFailed: u64 = 2;
    const ESumMismatch: u64 = 3;

    // --- Public Functions ---

    /// Verifies split with explicit amount reveals (PRODUCTION-SAFE)
    /// 
    /// This is the only secure way to verify a split operation.
    /// It requires the user to reveal all amounts and randomness values.
    /// 
    /// # How it prevents inflation attacks:
    /// 1. User must reveal input_amount and input_r
    /// 2. We verify Enc(input_amount, input_r) == input ciphertext
    /// 3. User must reveal output amounts (amount1, amount2)
    /// 4. We verify input_amount == amount1 + amount2
    /// 5. u64 type guarantees amounts are non-negative (implicit range proof)
    /// 
    /// # Privacy Trade-off:
    /// - Amounts are visible on-chain during the split
    /// - But linkability is still broken via fresh randomness
    /// 
    /// # Arguments
    /// * `input` - The input ciphertext to split
    /// * `input_amount` - The plaintext amount in the input
    /// * `input_r` - The randomness used to encrypt the input
    /// * `amount1` - The first output amount
    /// * `r1` - Randomness for first output
    /// * `amount2` - The second output amount
    /// * `r2` - Randomness for second output
    /// 
    /// # Returns
    /// Tuple of (output1_ciphertext, output2_ciphertext)
    /// 
    /// # Aborts
    /// - EInputProofFailed: If input ciphertext doesn't match claimed values
    /// - ESumMismatch: If input_amount != amount1 + amount2
    public fun verify_split_with_amounts(
        input: &Ciphertext,
        input_amount: u64,
        input_r: Element<Scalar>,
        amount1: u64,
        r1: Element<Scalar>,
        amount2: u64,
        r2: Element<Scalar>
    ): (Ciphertext, Ciphertext) {
        // 1. Verify input ciphertext matches claimed values
        assert!(core::verify_encryption(input, input_amount, input_r), EInputProofFailed);
        
        // 2. Verify sum preservation (implicit range check via u64)
        assert!(input_amount == amount1 + amount2, ESumMismatch);
        
        // 3. Construct verified output ciphertexts
        let out1 = core::encrypt(amount1, r1);
        let out2 = core::encrypt(amount2, r2);
        
        (out1, out2)
    }

    /// Verifies that a ciphertext difference equals zero with given randomness.
    /// 
    /// Used internally for homomorphic balance verification.
    /// 
    /// # Arguments
    /// * `input` - The input ciphertext
    /// * `out1` - First output ciphertext
    /// * `out2` - Second output ciphertext  
    /// * `r_delta` - The randomness difference: r_in - (r_out1 + r_out2)
    /// 
    /// # Note
    /// This function alone does NOT prevent inflation attacks.
    /// It only verifies homomorphic consistency, not value ranges.
    public fun verify_zero_balance(
        input: &Ciphertext,
        out1: &Ciphertext,
        out2: &Ciphertext,
        r_delta: Element<Scalar>
    ) {
        let sum_outs = core::add(out1, out2);
        let diff = core::sub(input, &sum_outs);
        assert!(core::verify_encryption(&diff, 0, r_delta), EZeroBalanceCheckFailed);
    }
}
