# 0xBlind

**Parallelized Probabilistic Privacy Protocol (P4) for Sui Network**

[![Sui](https://img.shields.io/badge/Sui-Move-blue)](https://sui.io)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

## What is 0xBlind?

0xBlind is a privacy protocol that enables confidential value transfers on Sui. It uses homomorphic encryption to allow on-chain verification of transactions without revealing the amounts being transferred.

**Key Features:**
- 🔐 **Private Balances**: Encrypt your SUI holdings
- 🔄 **Private Transfers**: Send SUI without revealing amounts
- ⚡ **Parallel Execution**: 64 sharded pools for scalability
- 🧮 **Homomorphic Verification**: Prove correctness without decryption

## Quick Start

### Prerequisites

- [Sui CLI](https://docs.sui.io/build/install) (v1.51.1 or compatible)
- Rust (for Sui toolchain)

### Build

```bash
cd 0xBlind
sui move build
```

### Test

```bash
sui move test
```

Expected output:
```
[ PASS ] blind::core_tests::test_homomorphic_addition
[ PASS ] blind::pool_tests::test_full_cycle
[ PASS ] blind::pool_tests::test_pool_creation_and_funding
[ PASS ] blind::pool_tests::test_split_functionality
[ PASS ] blind::pool_tests::test_split_with_rotation
Test result: OK. Total tests: 5; passed: 5; failed: 0
```

### Deploy to Testnet

```bash
sui client publish --gas-budget 100000000
```

## Usage

### 1. Shield (Deposit)

Convert public SUI to private balance:

```typescript
// Off-chain: Generate random scalar
const r = generateRandomScalar();

// On-chain: Call fund
await client.moveCall({
  target: `${PACKAGE_ID}::pool::fund`,
  arguments: [poolObject, coinObject, r],
});
// Returns: EncryptedRecord (private note)
```

### 2. Private Transfer (Split)

Split one private note into two:

```typescript
// Off-chain: Create new ciphertexts
const out1 = encrypt(40, r1);
const out2 = encrypt(60, r2);
const r_delta = r_in - (r1 + r2);

// On-chain: Call split
await client.moveCall({
  target: `${PACKAGE_ID}::pool::split`,
  arguments: [record, out1, out2, r_delta],
});
// Returns: Two new EncryptedRecords
```

### 3. Unshield (Withdraw)

Convert private balance back to public SUI:

```typescript
// On-chain: Reveal r and amount
await client.moveCall({
  target: `${PACKAGE_ID}::pool::withdraw`,
  arguments: [poolObject, record, r, amount],
});
// Returns: Coin<SUI>
```

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed technical documentation.

## Security

⚠️ **This is a prototype for educational/research purposes.**

Production deployment requires:
- Range proofs (Bulletproofs) to prevent negative balance exploits
- Cryptographic audit of BLS12-381 usage
- Secure H generator derivation (hash-to-curve)

## License

MIT

## Contributing

Contributions are welcome! Please open an issue or PR.
