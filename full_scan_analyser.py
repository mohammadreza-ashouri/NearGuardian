import asyncio
import json
import time
import requests
from py_near.account import Account

# --- Configuration ---
# IMPORTANT: For a real "full scan," you would ideally use a NEAR indexer
# or a custom solution that efficiently streams contract deployment events.
# Direct RPC queries like `get_recently_deployed_contracts` are generally
# inefficient for large-scale discovery on Mainnet due to rate limits and data volume.
NEAR_RPC_URL = "https://rpc.mainnet.near.org" # Switched to mainnet for consistency with scan.bash
NEARBLOCKS_API_BASE = "https://api.nearblocks.io/v1/" # Mainnet Nearblocks API (conceptual use)

# --- Vulnerability Patterns (Same as before, for completeness) ---
VULNERABILITY_PATTERNS = {
    "Rust": {
        "Reentrancy": ["Promise::new(", ".transfer(", ".function_call(", ".then(", "ext_contract::", "env::promise_batch_action_transfer", "env::promise_batch_action_function_call", "self.balance", "self.total_supply", "self.token_amounts",],
        "Access_Control_Bypass": ["pub fn admin_", "pub fn set_owner(", "pub fn update_code(", "pub fn withdraw_funds(", "pub fn pause_contract(", "pub fn migrate_state(", "assert!(env::predecessor_account_id() == self.owner", "assert!(self.owners.contains(&env::predecessor_account_id())", "#[private]", "#[payable] pub fn ",],
        "Integer_Overflow_Underflow": [".checked_add(", ".checked_sub(", ".wrapping_add(", ".wrapping_sub(", "as u64", "unsafe {",],
        "Timestamp_Dependence": ["env::block_timestamp()", "block_timestamp_nanos", "if current_timestamp > ", "if current_timestamp < ", "current_timestamp % ", "current_timestamp / ", "timestamp_threshold",],
        "Denial_of_Service": [".iter().for_each(", ".values().for_each(", ".keys().for_each(", ".clear();", "LookupMap::remove(", "LookupSet::remove(", "loop {", "while ", "assert!(condition, \"error\");", "env::panic_str(", "GAS_FOR_CALLBACK:",],
        "Front_Running_MEV": ["resolve_auction(", "claim_reward(", "execute_trade(", "set_price(",],
        "Arbitrary_External_Call": ["recipient_contract_id: near_sdk::AccountId", "method_name: String", "args: Vec<u8>", "Promise::new(recipient_contract_id).function_call(method_name.into_bytes(), args, ", "assert!(env::is_valid_account_id(",],
        "Hardcoded_Values": ["\"near\"", "\"token.testnet\"", "1000000000000000000000000", "1_000_000_000_000_000_000_000_000", "300_000_000_000_000", "0x[0-9a-fA-F]{40,}",],
        "Error_Handling_Issues": ["#[callback_result] call_result: Result<(), PromiseError>", ".then(Self::ext(", "unwrap()", "expect(",],
        "Unsafe_Rust_Usage": ["unsafe {", "unsafe fn",],
        "Default_Derivations": ["#[derive(Default)]", "LookupMap::new(",]
    },
    "AssemblyScript": {
        "Reentrancy": ["near.Promise.create(", ".transfer(", ".functionCall(", ".then(() => {", "context.contractName", "this.balance -= amount;",],
        "Access_Control_Bypass": ["if (context.sender != this.owner)", "if (!this.authorizedUsers.has(context.sender))", "function admin", "function setOwner(", "function updateCode(", "function withdrawFunds(", "function pauseContract(",],
        "Integer_Overflow_Underflow": ["a + b", "a - b", "a * b", "unchecked(", "Uint64Array",],
        "Timestamp_Dependence": ["context.blockTimestamp", "context.blockIndex", "Date.now()", "if (context.blockTimestamp > ", "context.blockTimestamp % ",],
        "Denial_of_Service": ["for (let i = 0; i < collection.length; i++)", "Map<string, MyStruct>", "array.splice(", "assert(", "logging.log(\"panic!\")",],
        "Front_Running_MEV": ["bid(", "finalizeAuction(", "swap(",],
        "Arbitrary_External_Call": ["accountId: string", "methodName: string", "args: Uint8Array", "near.Promise.create(accountId).functionCall(methodName, args, 0, context.prepaidGas / 2)",],
        "Hardcoded_Values": ["\"hardcoded_id.near\"", "\"ft.testnet\"", "BigInt(1000000000000000000000000)", "1000000000000000000000000n",],
        "Error_Handling_Issues": [".then(() => {", ".catch(() => {",]
    },
    "Wasm": {
        "Presence_of_Known_Vulnerable_Signatures": ["0xdeadbeef1234567890abcdef...",],
        "Unusual_Control_Flow": ["call_indirect", "br_table",],
        "Memory_Access_Patterns": ["i32.load", "i64.load", "f32.load", "i32.store", "i64.store", "f32.store", "memory.grow",],
        "External_Import_Inspection": ["env.log_str", "env.panic_str", "env.promise_batch_action_transfer", "env.promise_batch_action_function_call",]
    }
}


async def get_recently_deployed_contracts(since_timestamp: int = None) -> dict:
    """
    Finds recently deployed smart contracts.
    NOTE: This is a placeholder. For a true "full scan" on Mainnet,
    you would integrate with a dedicated NEAR indexer API that provides
    contract deployment events, rather than scanning transactions via RPC.
    The current implementation mocks results or uses a basic Nearblocks API call
    that might not be efficient or comprehensive for real-time deployment monitoring.
    """
    print(f"\nSearching for recently deployed contracts since {time.ctime(since_timestamp / 1_000_000_000) if since_timestamp else 'start of time'}...")
    new_contracts = {}
    try:
        # This is a basic example of using Nearblocks to find recent transactions.
        # It's NOT optimized for finding *all* contract deployments.
        response = requests.get(f"{NEARBLOCKS_API_BASE}/transactions", params={"limit": 50})
        response.raise_for_status()
        transactions_data = response.json()
        
        for tx in transactions_data.get('transactions', []):
            tx_timestamp_nanos = tx.get('block_timestamp')
            if since_timestamp and tx_timestamp_nanos <= since_timestamp:
                continue

            for action in tx.get('actions', []):
                if action.get('type') == 'DeployContract':
                    account_id = tx.get('receiver_account_id')
                    code_hash = action.get('DeployContract', {}).get('code_hash') 
                    if account_id and account_id not in new_contracts:
                        print(f"Detected DeployContract for {account_id} at {time.ctime(tx_timestamp_nanos / 1_000_000_000)}")
                        new_contracts[account_id] = {
                            'timestamp': tx_timestamp_nanos,
                            'code_hash': code_hash 
                        }
        
        # Mocking for immediate testing if API is insufficient or for local demonstration
        if not new_contracts:
            current_time_nanos = int(time.time() * 1_000_000_000)
            mock_contracts = {
                f"vulnerable-contract-{time.strftime('%Y%m%d%H%M%S', time.gmtime())}.testnet": { # Dynamic mock name
                    "timestamp": current_time_nanos - 1000 * 1_000_000_000,
                    "code_hash": "mock_hash_vuln_1"
                },
                f"safe-token-{time.strftime('%Y%m%d%H%M%S', time.gmtime())}.testnet": { # Dynamic mock name
                    "timestamp": current_time_nanos - 500 * 1_000_000_000,
                    "code_hash": "mock_hash_safe_1"
                }
            }
            new_contracts.update({
                k: v for k, v in mock_contracts.items() 
                if not since_timestamp or v['timestamp'] > since_timestamp
            })
            if new_contracts:
                print("INFO: Using mocked new contracts for demonstration.")

    except requests.exceptions.RequestException as e:
        print(f"Error fetching recent transactions from Nearblocks API: {e}")
        print("Falling back to local mocks for demonstration.")
        current_time_nanos = int(time.time() * 1_000_000_000)
        mock_contracts = {
            f"vulnerable-contract-{time.strftime('%Y%m%d%H%M%S', time.gmtime())}.testnet": {
                "timestamp": current_time_nanos - 1000 * 1_000_000_000,
                "code_hash": "mock_hash_vuln_1"
            },
            f"safe-token-{time.strftime('%Y%m%d%H%M%S', time.gmtime())}.testnet": {
                "timestamp": current_time_nanos - 500 * 1_000_000_000,
                "code_hash": "mock_hash_safe_1"
            }
        }
        new_contracts.update({
            k: v for k, v in mock_contracts.items() 
            if not since_timestamp or v['timestamp'] > since_timestamp
        })

    return new_contracts


async def get_contract_code_or_source(account_id: str) -> tuple[str, str | None] | tuple[None, None]:
    """
    Attempts to get source code (Rust/AssemblyScript) or Wasm bytecode.
    Returns (code_content, language_hint) or (None, None).
    This function currently provides mocked source code for specific contract IDs.
    """
    if "vulnerable-contract" in account_id:
        print(f"INFO: Providing mocked VULNERABLE Rust source for {account_id}")
        return """
        // Example of a potentially vulnerable Rust contract
        use near_sdk::{near, env, Promise, PromiseError, ext_contract, collections::LookupMap};
        
        #[near(contract_state)]
        #[derive(Default)]
        pub struct VulnerableContract {
            pub owner: near_sdk::AccountId,
            pub balance: u128,
            pub last_withdrawal_timestamp: u64,
            pub sensitive_data: LookupMap<near_sdk::AccountId, String>,
        }

        #[near]
        impl VulnerableContract {
            #[init]
            pub fn new(owner_id: near_sdk::AccountId) -> Self {
                Self {
                    owner: owner_id,
                    balance: 0,
                    last_withdrawal_timestamp: 0,
                    sensitive_data: LookupMap::new(b"s".to_vec()),
                }
            }

            #[payable]
            pub fn deposit(&mut self) {
                let amount = env::attached_deposit();
                self.balance += amount;
                env::log_str(format!("Deposited {} yoctoNEAR", amount).as_str());
            }

            // Potential Reentrancy vulnerability if state is not updated before external call
            // and if a malicious contract calls back into this function
            pub fn unsafe_withdraw(&mut self, amount: u128) -> Promise {
                assert!(self.balance >= amount, "Not enough balance");
                // Vulnerable: Balance update after external call
                // self.balance -= amount; // Correct place would be here
                
                let recipient = env::predecessor_account_id();
                env::log_str(format!("Attempting unsafe withdrawal of {} yoctoNEAR to {}", amount, recipient).as_str());
                
                // Simulate an external call
                Promise::new(recipient.clone()).transfer(amount)
                    .then(
                        Self::ext(env::current_account_id())
                            .on_withdraw_callback(amount, recipient)
                    )
            }

            #[private]
            pub fn on_withdraw_callback(&mut self, amount: u128, recipient: near_sdk::AccountId, #[callback_result] call_result: Result<(), PromiseError>) -> bool {
                if call_result.is_err() {
                    env::log_str(format!("Withdrawal to {} failed. Refunding {}.", recipient, amount).as_str());
                    // In a real vulnerability, the balance might already be decremented here.
                    // This mock assumes it's decremented in the first call if it were secure.
                    // If the first call *didn't* decrement, this is where the reentrancy happens.
                    return false;
                } else {
                    env::log_str(format!("Withdrawal to {} successful.", recipient).as_str());
                    // Vulnerable point: State update happens AFTER the external call has potentially re-entered
                    self.balance -= amount; 
                    true
                }
            }

            // Timestamp dependence vulnerability
            pub fn lottery_draw(&mut self) -> near_sdk::AccountId {
                let current_timestamp = env::block_timestamp(); // Vulnerable: Relying on block.timestamp for critical logic
                env::log_str(format!("Lottery draw at timestamp: {}", current_timestamp).as_str());
                
                if current_timestamp % 2 == 0 { // Simplistic, but shows reliance
                    env::signer_account_id()
                } else {
                    self.owner.clone()
                }
            }

            // Improper Access Control
            pub fn change_owner(&mut self, new_owner: near_sdk::AccountId) {
                // assert_eq!(env::predecessor_account_id(), self.owner, "Only owner can change owner"); # Missing check!
                self.owner = new_owner;
                env::log_str(format!("Owner changed to {}", new_owner).as_str());
            }

            #[view]
            pub fn get_balance(&self) -> u128 {
                self.balance
            }
            
            // Example of an integer overflow vulnerability (if not using safe math)
            pub fn add_supply(&mut self, amount: u128) {
                // In Rust, u128 handles large numbers, but conceptually, if a smaller type was used:
                // self.balance = self.balance.wrapping_add(amount); # Correct usage
                // Vulnerable if simply `self.balance + amount` and `self.balance` was a smaller int
                // and `amount` could cause overflow without a wrapping_add or panic.
                self.balance += amount; 
            }

            // Example of using unsafe (requires careful auditing)
            // unsafe fn perform_low_level_action(&mut self) {
            //    // Potentially dangerous code here
            //    env::log_str("Performing unsafe action.");
            // }
        }
        """, "Rust"
    elif "safe-token" in account_id:
        print(f"INFO: Providing mocked SAFE Rust source for {account_id}")
        return """
        // Example of a relatively safe Rust contract (simplified FT standard)
        use near_sdk::{near, env, Promise, BorshStorageKey};
        use near_sdk::collections::LookupMap;
        
        #[near(contract_state)]
        #[derive(Default)]
        pub struct SafeToken {
            pub owner: near_sdk::AccountId,
            pub total_supply: u128,
            pub balances: LookupMap<near_sdk::AccountId, u128>,
        }

        #[near]
        impl SafeToken {
            #[init]
            pub fn new(owner_id: near_sdk::AccountId, initial_supply: u128) -> Self {
                Self {
                    owner: owner_id,
                    total_supply: initial_supply,
                    balances: {
                        let mut balances = LookupMap::new(b"b".to_vec());
                        balances.insert(&owner_id, &initial_supply);
                        balances
                    },
                }
            }

            #[payable]
            pub fn transfer(&mut self, receiver_id: near_sdk::AccountId, amount: u128) {
                let sender_id = env::predecessor_account_id();
                let sender_balance = self.balances.get(&sender_id).unwrap_or(0);
                assert!(sender_balance >= amount, "Not enough tokens");

                // Correct state updates before any potential external calls
                self.balances.insert(&sender_id, &(sender_balance - amount));
                let receiver_balance = self.balances.get(&receiver_id).unwrap_or(0);
                self.balances.insert(&receiver_id, &(receiver_balance + amount));

                env::log_str(format!("Transferred {} tokens from {} to {}", amount, sender_id, receiver_id).as_str());
            }

            #[view]
            pub fn get_balance(&self, account_id: near_sdk::AccountId) -> u128 {
                self.balances.get(&account_id).unwrap_or(0)
            }

            #[view]
            pub fn get_total_supply(&self) -> u128 {
                self.total_supply
            }
        }
        """, "Rust"
    else:
        # Fallback: Attempt to fetch Wasm bytecode if source is not available.
        # In a real system, you'd use a NEAR RPC query for view_code
        # For this demo, we'll just return generic Wasm.
        print(f"INFO: Could not find source code for {account_id}. Mocking Wasm bytecode.")
        # Simulating fetching actual code from RPC:
        try:
            response = requests.post(
                NEAR_RPC_URL,
                headers={"Content-Type": "application/json"},
                json={
                    "jsonrpc": "2.0",
                    "id": "dontcare",
                    "method": "query",
                    "params": {
                        "request_type": "view_code",
                        "finality": "final",
                        "account_id": account_id
                    }
                }
            )
            response.raise_for_status()
            result = response.json().get('result', {})
            code_base64 = result.get('code_base64')
            if code_base64:
                print(f"INFO: Successfully fetched Wasm for {account_id} from RPC.")
                return code_base64, "Wasm" # return base64 string
            else:
                print(f"WARNING: RPC query for {account_id} returned no code_base64. Using generic mock.")
                return b"MOCKED_GENERIC_WASM_BYTECODE", "Wasm" # Return bytes for generic mock
        except requests.exceptions.RequestException as e:
            print(f"ERROR: Failed to fetch Wasm for {account_id} via RPC: {e}. Using generic mock.")
            return b"MOCKED_GENERIC_WASM_BYTECODE", "Wasm"


async def analyze_contract_for_vulnerabilities(contract_id: str, code_content: str, language_hint: str) -> list[str]:
    """
    Performs security analysis based on the contract code and language hint.
    """
    vulnerabilities = []
    
    print(f"INFO: Analyzing contract {contract_id} (Language: {language_hint})...")

    if language_hint in VULNERABILITY_PATTERNS:
        lang_patterns = VULNERABILITY_PATTERNS[language_hint]
        for vuln_type, patterns in lang_patterns.items():
            for pattern in patterns:
                if pattern in code_content:
                    if vuln_type == "Reentrancy":
                        if "Promise::new(" in pattern or ".transfer(" in pattern or ".function_call(" in pattern:
                            vulnerabilities.append(f"Potential {vuln_type} (External Call): Found '{pattern}'. Review order of operations (Checks-Effects-Interactions). State changes *after* external calls are risky.")
                        elif ".then(" in pattern:
                            vulnerabilities.append(f"Potential {vuln_type} (Callback): Found '{pattern}'. State changes in promise callbacks require careful auditing for reentrancy.")
                        else:
                            vulnerabilities.append(f"Potential {vuln_type}: Found '{pattern}'. Investigate related external calls and state changes.")

                    elif vuln_type == "Access_Control_Bypass":
                        if "pub fn admin_" in pattern or "pub fn set_owner(" in pattern or "pub fn update_code(" in pattern or "pub fn withdraw_funds(" in pattern:
                            vulnerabilities.append(f"Potential {vuln_type} (Sensitive Function): Found function '{pattern}'. Ensure robust access control checks (e.g., `assert!(predecessor == owner)`).")
                        elif "#[private]" in pattern:
                            vulnerabilities.append(f"Potential {vuln_type} (Missing Private): Sensitive function may be missing `#[private]` attribute, allowing unauthorized external calls.")
                        else:
                            vulnerabilities.append(f"Potential {vuln_type}: Found '{pattern}'. Review authorization logic for sensitive operations.")

                    elif vuln_type == "Integer_Overflow_Underflow":
                        if "as u64" in pattern or "unsafe {" in pattern:
                            vulnerabilities.append(f"Potential {vuln_type} (Unsafe Operation): Found '{pattern}'. Arithmetic operations within `unsafe` blocks or with explicit type casting can lead to unchecked overflow/underflow.")
                        else:
                            vulnerabilities.append(f"Potential {vuln_type}: Found '{pattern}'. Ensure all arithmetic operations use `checked_*` or `wrapping_*` methods where appropriate.")

                    elif vuln_type == "Timestamp_Dependence":
                        vulnerabilities.append(f"Potential {vuln_type}: Found '{pattern}'. Relying on `env::block_timestamp()` for critical logic (e.g., randomness, vesting) can be exploited by block producers.")

                    elif vuln_type == "Denial_of_Service":
                        if ".iter().for_each(" in pattern or "LookupMap::remove(" in pattern:
                            vulnerabilities.append(f"Potential {vuln_type} (Unbounded Loop/Expensive Operation): Found '{pattern}'. Iterating over or modifying large collections can lead to high gas costs and block legitimate calls.")
                        else:
                            vulnerabilities.append(f"Potential {vuln_type}: Found '{pattern}'. Review for operations that could consume excessive gas or cause unintended reverts.")

                    elif vuln_type == "Front_Running_MEV":
                        vulnerabilities.append(f"Potential {vuln_type}: Found '{pattern}'. Functions handling time-sensitive or competitive operations (e.g., auctions, claims) may be susceptible to front-running.")

                    elif vuln_type == "Arbitrary_External_Call":
                        vulnerabilities.append(f"Potential {vuln_type}: Found '{pattern}'. Allowing users to define arbitrary `recipient_contract_id` and `method_name` can lead to unintended execution on other contracts. Implement strict validation.")

                    elif vuln_type == "Hardcoded_Values":
                        vulnerabilities.append(f"Potential {vuln_type}: Found hardcoded value '{pattern}'. Critical parameters (e.g., contract IDs, amounts) should ideally be configurable or derived securely, not hardcoded.")

                    elif vuln_type == "Error_Handling_Issues":
                        vulnerabilities.append(f"Potential {vuln_type}: Found '{pattern}'. Inadequate error handling in promise callbacks or for external calls can lead to unexpected state or unrecoverable funds.")

                    elif vuln_type == "Unsafe_Rust_Usage":
                        vulnerabilities.append(f"Potential {vuln_type}: Found '{pattern}'. Presence of `unsafe` blocks necessitates meticulous manual security review as Rust's safety guarantees are bypassed.")

                    elif vuln_type == "Default_Derivations":
                        vulnerabilities.append(f"Potential {vuln_type}: Found '{pattern}'. Using `#[derive(Default)]` on structs containing collections (e.g., LookupMap) can lead to uninitialized state if `new` is not explicitly called in `init`.")

    else:
        vulnerabilities.append(f"WARNING: No specific vulnerability patterns defined for language: {language_hint}. Manual review recommended.")

    return vulnerabilities


async def scan_known_contract(account_id: str):
    """
    Scans a pre-defined known contract for demonstration purposes.
    """
    print(f"\n--- Scanning known contract: {account_id} ---")
    code_content, language_hint = await get_contract_code_or_source(account_id)

    if code_content:
        # If the code_content is base64 string (from RPC for Wasm), decode it for analysis
        if language_hint == "Wasm" and isinstance(code_content, str):
            import base64
            # For actual Wasm analysis, you'd need a specialized disassembler/analyzer.
            # Here, we're simply decoding to bytes to match the pattern for mocking,
            # but string search on raw bytes is not ideal for Wasm.
            code_content = base64.b64decode(code_content).decode(errors='ignore')
            
        vulnerabilities = await analyze_contract_for_vulnerabilities(account_id, code_content, language_hint)
        if vulnerabilities:
            print(f"\n🚨 {account_id} - FOUND VULNERABILITIES:")
            for vuln in set(vulnerabilities):
                print(f"- {vuln}")
        else:
            print(f"\n✅ {account_id} - No common vulnerability patterns detected (based on string matching).")
    else:
        print(f"❌ Could not retrieve code/source for {account_id}.")


async def main_full_scan():
    """
    This function continuously monitors for new contract deployments
    and analyzes them. It's intended to run as a long-lived service.
    """
    last_scanned_timestamp = None # To track the last time we scanned, in nanoseconds

    try:
        # Initializing Account to establish RPC connection
        dummy_private_key = "ed25519:2uGikf2Kk8TddyN811N33h329yW7T6u4n7rG7uQ4wG3uL8u3V8t8Q6x6S7e4z4c4b4a3c3e3f3g3h3i3j3k3l3m3n3o3p3q3r3s3t3u3v3w3x3y3z30313233343536373839"
        account = Account(account_id="test.near", private_key=dummy_private_key, rpc_addr=NEAR_RPC_URL)
        print(f"Connected to NEAR RPC at {NEAR_RPC_URL}")
    except Exception as e:
        print(f"Failed to connect to NEAR RPC. Some functions might be limited: {e}")
        print("Please ensure py_near is correctly installed and the RPC URL is accessible.")
        account = None

    while True:
        print(f"\n--- Initiating new full scan cycle (Last scanned: {time.ctime(last_scanned_timestamp / 1_000_000_000) if last_scanned_timestamp else 'Never'}) ---")
        
        try:
            # 1. Discover recently deployed contracts
            # In a true "full scan" agent, this would be replaced by:
            # - Subscribing to indexer feeds for new deployments
            # - More robust block/transaction scanning than simple Nearblocks API calls
            newly_deployed = await get_recently_deployed_contracts(since_timestamp=last_scanned_timestamp)

            if newly_deployed:
                print(f"Found {len(newly_deployed)} new/updated contracts since last scan.")
                for contract_id, details in newly_deployed.items():
                    print(f"Processing new contract: {contract_id}")
                    # Fetch and analyze the contract
                    code_content, language_hint = await get_contract_code_or_source(contract_id)

                    if code_content:
                        # Decode Wasm from base64 if it came from RPC
                        if language_hint == "Wasm" and isinstance(code_content, str):
                            import base64
                            code_content = base64.b64decode(code_content).decode(errors='ignore') # Decode for string search
                        elif isinstance(code_content, bytes): # If it's bytes from a direct mock
                            code_content = code_content.decode(errors='ignore')
                            
                        vulnerabilities = await analyze_contract_for_vulnerabilities(contract_id, code_content, language_hint)
                        if vulnerabilities:
                            print(f"\n🚨 VULNERABILITY ALERT for {contract_id}:")
                            for vuln in set(vulnerabilities):
                                print(f"- {vuln}")
                        else:
                            print(f"✅ {contract_id}: No common vulnerability patterns detected (based on string matching).")
                    else:
                        print(f"❌ Could not retrieve code/source for {contract_id}. Skipping analysis.")
            else:
                print("No new contracts detected since last scan.")

            # Update the last scanned timestamp to the latest timestamp found
            if newly_deployed:
                latest_timestamp = max(details['timestamp'] for details in newly_deployed.values())
                if last_scanned_timestamp is None or latest_timestamp > last_scanned_timestamp:
                    last_scanned_timestamp = latest_timestamp
            else:
                last_scanned_timestamp = int(time.time() * 1_000_000_000)

        except Exception as e:
            print(f"\nAn unexpected error occurred during the scanning cycle: {e}")
            print("Attempting to continue in the next cycle...")
            last_scanned_timestamp = int(time.time() * 1_000_000_000)

        # Scan some pre-defined "known" contracts to ensure they are always checked
        # These are your mocked vulnerable/safe contracts
        await scan_known_contract("vulnerable-contract-20250615.testnet")
        await scan_known_contract("safe-token-20250615.testnet")

        print("\nSleeping for 60 seconds before next full scan cycle...")
        await asyncio.sleep(60) # Scan every 60 seconds

if __name__ == "__main__":
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            print("INFO: Event loop already running, scheduling main_full_scan() as a task.")
            loop.create_task(main_full_scan())
        else:
            asyncio.run(main_full_scan())
    except RuntimeError as e:
        if "There is no current event loop in thread" in str(e):
            print("INFO: No active event loop found, creating and running a new one.")
            asyncio.run(main_full_scan())
        else:
            raise
    except Exception as e:
        print(f"An error occurred while starting the asyncio loop for full scan: {e}")