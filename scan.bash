#!/bin/bash

echo "🔍 Finding ACTIVE contracts in recent NEAR blocks..."

# Get latest block height
LATEST_BLOCK=$(curl -s -X POST https://rpc.mainnet.near.org \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"1","method":"block","params":{"finality":"final"}}' | \
  jq -r '.result.header.height')

echo "📊 Starting from block: $LATEST_BLOCK"
echo "🔄 Scanning last 50 blocks for active contracts..."

CONTRACTS_FOUND=0
CURRENT_BLOCK=$LATEST_BLOCK

# Create temp file to track found contracts (instead of associative array)
TEMP_CONTRACTS="/tmp/near_contracts_found.txt"
rm -f "$TEMP_CONTRACTS"
touch "$TEMP_CONTRACTS"

# Search backwards through recent blocks
for i in $(seq 0 50); do
  CURRENT_BLOCK=$((LATEST_BLOCK - i))
  
  # Get block data
  BLOCK_DATA=$(curl -s --max-time 8 -X POST https://rpc.mainnet.near.org \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"block\",\"params\":{\"block_id\":$CURRENT_BLOCK}}")
  
  # Extract chunk hashes
  CHUNK_HASHES=$(echo "$BLOCK_DATA" | jq -r '.result.chunks[].chunk_hash' 2>/dev/null)
  
  # Check each chunk for transactions
  for CHUNK_HASH in $CHUNK_HASHES; do
    if [ ! -z "$CHUNK_HASH" ] && [ "$CHUNK_HASH" != "null" ]; then
      CHUNK_DATA=$(curl -s --max-time 5 -X POST https://rpc.mainnet.near.org \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"chunk\",\"params\":{\"chunk_id\":\"$CHUNK_HASH\"}}")
      
      # Get all receiver accounts (potential contracts)
      RECEIVER_ACCOUNTS=$(echo "$CHUNK_DATA" | jq -r '.result.transactions[]?.receiver_id' 2>/dev/null)
      
      # Check each receiver to see if it's a contract
      for ACCOUNT in $RECEIVER_ACCOUNTS; do
        if [ ! -z "$ACCOUNT" ] && [ "$ACCOUNT" != "null" ]; then
          
          # Skip if already found
          if grep -q "^$ACCOUNT$" "$TEMP_CONTRACTS" 2>/dev/null; then
            continue
          fi
          
          # Skip obvious non-contracts (personal accounts with numbers/dots)
          case "$ACCOUNT" in
            *.testnet) continue ;;
            *[0-9][0-9][0-9][0-9]*) continue ;;  # Skip accounts with many numbers
          esac
          
          # Check if this account has contract code
          echo "🔍 Checking: $ACCOUNT"
          CODE_CHECK=$(curl -s --max-time 3 -X POST https://rpc.mainnet.near.org \
            -H "Content-Type: application/json" \
            -d "{\"jsonrpc\":\"2.0\",\"id\":\"1\",\"method\":\"query\",\"params\":{\"request_type\":\"view_code\",\"finality\":\"final\",\"account_id\":\"$ACCOUNT\"}}")
          
          CODE_BASE64=$(echo "$CODE_CHECK" | jq -r '.result.code_base64' 2>/dev/null)
          
          # If it has code, it's a contract!
          if [ "$CODE_BASE64" != "null" ] && [ "$CODE_BASE64" != "" ] && [ ${#CODE_BASE64} -gt 100 ]; then
            CONTRACTS_FOUND=$((CONTRACTS_FOUND + 1))
            echo "$ACCOUNT" >> "$TEMP_CONTRACTS"
            
            echo "✅ Active Contract $CONTRACTS_FOUND: $ACCOUNT"
            echo "   📍 Active in block: $CURRENT_BLOCK"
            echo "   📏 Code size: ${#CODE_BASE64} bytes (base64)"
            
            # Try to identify what type of transaction was sent to it
            TX_DETAILS=$(echo "$CHUNK_DATA" | jq -r --arg acc "$ACCOUNT" '
              .result.transactions[]? | 
              select(.receiver_id == $acc) | 
              .actions[]? | keys[]' 2>/dev/null | head -1)
            
            if [ ! -z "$TX_DETAILS" ]; then
              echo "   🔄 Transaction type: $TX_DETAILS"
            fi
            
            echo ""
            
            # Stop after finding 5 active contracts
            if [ $CONTRACTS_FOUND -ge 5 ]; then
              break 3
            fi
          fi
          
          # Small delay to avoid rate limiting
          sleep 0.2
        fi
      done
    fi
  done
  
  # Progress update every 10 blocks
  if [ $((i % 10)) -eq 0 ]; then
    echo "🔄 Scanned $i blocks, found $CONTRACTS_FOUND active contracts..."
  fi
done

# Cleanup
rm -f "$TEMP_CONTRACTS"

echo ""
echo "🎯 Scan complete!"
echo "📊 Blocks scanned: 50"
echo "📈 Active contracts found: $CONTRACTS_FOUND"

if [ $CONTRACTS_FOUND -gt 0 ]; then
  echo ""
  echo "💡 Next steps:"
  echo "   • Pick any contract above to analyze"
  echo "   • Run: ./analyze_contract.bash CONTRACT_NAME"
fi