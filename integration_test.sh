#!/bin/bash
set -e

# Load IDs
PACKAGE_ID="0x5ec6bcfdc0518a56fcda6fb86ed21b02807dca8bda9ae7248c130e972b1c660a"
POOL_ID="0x0a7be4a9f915bac0483d3e36b0be94f1b40fd7e6b58dced62d7f820c37520142"
TEST_ADDR="0xb82d6c61ae96d22d498090daac2143cf20dbef997375c4b0c7a19ecc1dc3d9fc"

echo "--- Testing 0xBlind Protocol ---"
echo "Package: $PACKAGE_ID"
echo "Pool: $POOL_ID"
echo "Test Address: $TEST_ADDR"

# 1. Fund (Shield)
echo "1. Funding 10,000,000 MIST (0.01 SUI)..."
# Randomness r = 123
R_HEX="[123,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]" 
PAYMENT_ID=$(sui client gas --json | jq -r '.[0].gasCoinId')

echo "Using Gas Object: $PAYMENT_ID"

sui client call --package $PACKAGE_ID --module pool --function fund \
    --args $POOL_ID $PAYMENT_ID "$R_HEX" \
    --gas-budget 50000000 --json > fund_tx.json

RECORD_ID=$(cat fund_tx.json | jq -r '.objectChanges[] | select(.objectType | contains("::pool::EncryptedRecord")) | .objectId')
echo "Funded! EncryptedRecord created: $RECORD_ID"

# 2. Split
echo "2. Splitting Record into 4M and 6M..."
# Amount1 = 4,000,000, R1 = 1
# Amount2 = 6,000,000, R2 = 2
# Input R = 123
R1_HEX="[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]"
R2_HEX="[2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]"

sui client call --package $PACKAGE_ID --module pool --function split \
    --args $RECORD_ID "$R_HEX" 4000000 "$R1_HEX" 6000000 "$R2_HEX" \
    --gas-budget 50000000 --json > split_tx.json

OUT1_ID=$(cat split_tx.json | jq -r '.objectChanges[] | select(.type == "created" and (.objectType | contains("::pool::EncryptedRecord"))) | .objectId' | sed -n '1p')
OUT2_ID=$(cat split_tx.json | jq -r '.objectChanges[] | select(.type == "created" and (.objectType | contains("::pool::EncryptedRecord"))) | .objectId' | sed -n '2p')

echo "Split Successful!"
echo "Out1 (4M): $OUT1_ID"
echo "Out2 (6M): $OUT2_ID"

# 3. Withdraw
echo "3. Withdrawing 4M from Out1..."
sui client call --package $PACKAGE_ID --module pool --function withdraw \
    --args $POOL_ID $OUT1_ID "$R1_HEX" 4000000 \
    --gas-budget 50000000 --json > withdraw_tx.json

echo "Withdraw Successful! Funds are back to public SUI."
echo "--- Test Complete ---"
