/// 0xBlind Pool Module
/// Manages sharded privacy pools and encrypted balance records.
/// 
/// Architecture:
/// - 64 shared Pool objects for parallel transaction processing
/// - EncryptedRecord owned objects for user balances
/// - Homomorphic verification for private transfers
#[allow(duplicate_alias, lint(self_transfer))]
module blind::pool {
    use sui::object::{Self, UID};
    use sui::balance::{Self, Balance};
    use sui::coin::{Self, Coin};
    use sui::sui::SUI;
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;
    use sui::event;
    use sui::group_ops::Element;
    use sui::bls12381::Scalar;
    use blind::core::{Self, Ciphertext};

    // --- Constants ---
    
    /// Number of parallel privacy pools (shards)
    const SHARD_COUNT: u64 = 64;
    
    // --- Error Codes ---
    
    /// Proof verification failed during withdrawal
    const EInvalidProof: u64 = 0;
    /// Cannot fund with zero amount
    const EZeroAmount: u64 = 1;
    /// Pool has insufficient balance for withdrawal
    const EInsufficientPoolBalance: u64 = 2;

    // --- Events ---

    /// Emitted when a user shields SUI into the privacy pool
    public struct FundEvent has copy, drop {
        pool_id: address,
        shard_id: u64,
        amount: u64,
        sender: address,
    }

    /// Emitted when a user splits an encrypted record
    public struct SplitEvent has copy, drop {
        input_record_id: address,
        output1_record_id: address,
        output2_record_id: address,
        sender: address,
    }

    /// Emitted when a user unshields SUI from the privacy pool
    public struct WithdrawEvent has copy, drop {
        pool_id: address,
        shard_id: u64,
        amount: u64,
        recipient: address,
    }

    // --- Structs ---

    /// Shared Object: Privacy Pool Shard
    /// Holds the physical SUI tokens for the protocol.
    /// 64 shards enable parallel transaction processing.
    public struct Pool has key {
        id: UID,
        balance: Balance<SUI>,
        shard_id: u64,
    }

    /// Owned Object: Encrypted Balance Record (Shielded UTXO)
    /// Represents a user's private balance.
    /// Contains encrypted amount that only the owner can spend.
    public struct EncryptedRecord has key, store {
        id: UID,
        /// Encrypted balance: Enc(amount, randomness)
        cipher_balance: Ciphertext,
        /// Pool shard this record was funded from (for withdrawal routing)
        source_shard: u64,
    }

    // --- Init ---

    /// Initializes 64 Privacy Pool shards as shared objects.
    /// Called automatically on package publish.
    fun init(ctx: &mut TxContext) {
        let mut i = 0;
        while (i < SHARD_COUNT) {
            let pool = Pool {
                id: object::new(ctx),
                balance: balance::zero(),
                shard_id: i,
            };
            transfer::share_object(pool);
            i = i + 1;
        };
    }

    // --- Entry Functions ---

    /// Shield: Convert public SUI to private EncryptedRecord
    /// 
    /// # Arguments
    /// * `pool` - The pool shard to deposit into
    /// * `payment` - The SUI coin to shield
    /// * `r` - Random scalar for encryption (must be kept secret by user)
    /// 
    /// # Effects
    /// - Deposits SUI into pool balance
    /// - Creates and transfers EncryptedRecord to sender
    /// - Emits FundEvent
    /// 
    /// # Aborts
    /// - EZeroAmount if payment is 0
    public fun fund(
        pool: &mut Pool,
        payment: Coin<SUI>,
        r: Element<Scalar>,
        ctx: &mut TxContext
    ) {
        let amount = coin::value(&payment);
        assert!(amount > 0, EZeroAmount);
        
        let sender = tx_context::sender(ctx);
        let pool_addr = object::uid_to_address(&pool.id);
        
        // 1. Encrypt the amount
        let encrypted_bal = core::encrypt(amount, r);

        // 2. Deposit SUI into pool
        let coin_balance = coin::into_balance(payment);
        balance::join(&mut pool.balance, coin_balance);

        // 3. Create EncryptedRecord with source shard tracking
        let record = EncryptedRecord {
            id: object::new(ctx),
            cipher_balance: encrypted_bal,
            source_shard: pool.shard_id,
        };

        // 4. Emit event for indexing
        event::emit(FundEvent {
            pool_id: pool_addr,
            shard_id: pool.shard_id,
            amount,
            sender,
        });

        // 5. Transfer record to user
        transfer::public_transfer(record, sender);
    }

    /// Split: Divide one encrypted record into two (PRODUCTION-SAFE)
    /// 
    /// This function requires revealing amounts to prevent inflation attacks.
    /// The amounts are verified on-chain to ensure no value is created from nothing.
    /// 
    /// # Arguments
    /// * `record` - The input record to split (consumed)
    /// * `input_r` - Randomness used when creating the input record
    /// * `amount1` - First output amount (plaintext)
    /// * `r1` - Randomness for first output
    /// * `amount2` - Second output amount (plaintext)
    /// * `r2` - Randomness for second output
    /// 
    /// # Effects
    /// - Verifies input ciphertext matches claimed values
    /// - Verifies amount1 + amount2 == input_amount
    /// - Destroys input record
    /// - Creates two new EncryptedRecords with verified amounts
    /// - Emits SplitEvent
    public fun split(
        record: EncryptedRecord,
        input_r: Element<Scalar>,
        amount1: u64,
        r1: Element<Scalar>,
        amount2: u64,
        r2: Element<Scalar>,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        let input_addr = object::uid_to_address(&record.id);
        let source_shard = record.source_shard;
        
        // 1. Unpack input record
        let EncryptedRecord { id, cipher_balance: input_cipher, source_shard: _ } = record;
        
        // 2. Calculate input amount from outputs
        let input_amount = amount1 + amount2;
        
        // 3. Verify with amounts - prevents inflation attacks
        let (out1_cipher, out2_cipher) = blind::proof::verify_split_with_amounts(
            &input_cipher,
            input_amount,
            input_r,
            amount1,
            r1,
            amount2,
            r2
        );
        
        // 4. Delete input record
        object::delete(id);

        // 5. Create new records with verified ciphertexts
        let out1 = EncryptedRecord { 
            id: object::new(ctx), 
            cipher_balance: out1_cipher,
            source_shard,
        };
        let out2 = EncryptedRecord { 
            id: object::new(ctx), 
            cipher_balance: out2_cipher,
            source_shard,
        };

        let out1_addr = object::uid_to_address(&out1.id);
        let out2_addr = object::uid_to_address(&out2.id);

        // 6. Emit event
        event::emit(SplitEvent {
            input_record_id: input_addr,
            output1_record_id: out1_addr,
            output2_record_id: out2_addr,
            sender,
        });

        // 7. Transfer outputs to sender
        transfer::public_transfer(out1, sender);
        transfer::public_transfer(out2, sender);
    }

    /// Withdraw: Convert private EncryptedRecord back to public SUI
    /// 
    /// User must reveal the encryption parameters (r and amount) to prove ownership.
    /// This deanonymizes the specific record but allows accessing the funds.
    /// 
    /// # Arguments
    /// * `pool` - The pool to withdraw from (should match record's source_shard)
    /// * `record` - The encrypted record to unshield (consumed)
    /// * `r` - The randomness used during encryption
    /// * `amount` - The amount encrypted in the record
    /// 
    /// # Effects
    /// - Verifies Enc(amount, r) matches record
    /// - Destroys record
    /// - Transfers SUI coin to sender
    /// - Emits WithdrawEvent
    /// 
    /// # Aborts
    /// - EInvalidProof if encryption doesn't match
    /// - EInsufficientPoolBalance if pool lacks funds
    public fun withdraw(
        pool: &mut Pool,
        record: EncryptedRecord,
        r: Element<Scalar>,
        amount: u64,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        let pool_addr = object::uid_to_address(&pool.id);
        
        // 1. Unpack record
        let EncryptedRecord { id, cipher_balance, source_shard: _ } = record;
        object::delete(id);

        // 2. Verify the opening: does Enc(amount, r) == cipher_balance?
        let is_valid = core::verify_encryption(&cipher_balance, amount, r);
        assert!(is_valid, EInvalidProof);

        // 3. Check pool has sufficient balance
        assert!(balance::value(&pool.balance) >= amount, EInsufficientPoolBalance);

        // 4. Release funds
        let withdrawn_balance = balance::split(&mut pool.balance, amount);
        let withdrawn_coin = coin::from_balance(withdrawn_balance, ctx);

        // 5. Emit event
        event::emit(WithdrawEvent {
            pool_id: pool_addr,
            shard_id: pool.shard_id,
            amount,
            recipient: sender,
        });

        // 6. Transfer coin to user
        transfer::public_transfer(withdrawn_coin, sender);
    }

    // --- View Functions ---

    /// Get the shard ID of a pool
    public fun get_shard_id(pool: &Pool): u64 {
        pool.shard_id
    }

    /// Get the total balance held in a pool
    public fun get_pool_balance(pool: &Pool): u64 {
        balance::value(&pool.balance)
    }

    /// Get the source shard of an encrypted record
    public fun get_record_source_shard(record: &EncryptedRecord): u64 {
        record.source_shard
    }

    /// Get the ciphertext from an encrypted record
    public fun get_ciphertext(record: &EncryptedRecord): &Ciphertext {
        &record.cipher_balance
    }
}
