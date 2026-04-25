# API Clients

## Overview

The API clients module provides interfaces for interacting with Movement network services: the fullnode REST API, the faucet service, and the indexer GraphQL API.

## Goals

1. Full coverage of Movement REST API
2. Type-safe request/response handling
3. Proper error handling with context
4. Support for all network environments

## Non-Goals

- WebSocket subscriptions (future feature)
- Caching layer (user responsibility)
- Rate limiting (handled by server)

---

## API Design

### MovementConfig

```rust
/// Network configuration for API clients.
#[derive(Clone, Debug)]
pub struct MovementConfig {
    fullnode_url: Url,
    faucet_url: Option<Url>,
    indexer_url: Option<Url>,
    timeout: Duration,
}

impl MovementConfig {
    /// Create configuration for mainnet.
    pub fn mainnet() -> Self;
    
    /// Create configuration for testnet.
    pub fn testnet() -> Self;
    
    /// Create configuration for devnet.
    pub fn devnet() -> Self;
    
    /// Create configuration for local network.
    pub fn localnet() -> Self;
    
    /// Create custom configuration.
    pub fn custom(fullnode_url: impl Into<Url>) -> Self;
    
    /// Set faucet URL.
    pub fn with_faucet(self, url: impl Into<Url>) -> Self;
    
    /// Set indexer URL.
    pub fn with_indexer(self, url: impl Into<Url>) -> Self;
    
    /// Set request timeout.
    pub fn with_timeout(self, timeout: Duration) -> Self;
}
```

### Movement (High-Level Client)

```rust
/// Unified Movement client combining all services.
pub struct Movement {
    config: MovementConfig,
    fullnode: MovementFullnodeClient,
    #[cfg(feature = "faucet")]
    faucet: Option<MovementFaucetClient>,
    #[cfg(feature = "indexer")]
    indexer: Option<MovementIndexerClient>,
    chain_id: ChainId,
}

impl Movement {
    /// Create a new Movement client.
    pub async fn new(config: MovementConfig) -> Result<Self, MovementError>;
    
    /// Get the chain ID.
    pub fn chain_id(&self) -> ChainId;
    
    /// Get the fullnode client.
    pub fn fullnode(&self) -> &MovementFullnodeClient;
    
    /// Get the faucet client (if available).
    #[cfg(feature = "faucet")]
    pub fn faucet(&self) -> Option<&MovementFaucetClient>;
    
    /// Get the indexer client (if available).
    #[cfg(feature = "indexer")]
    pub fn indexer(&self) -> Option<&MovementIndexerClient>;
    
    // Convenience methods
    
    /// Get account balance in APT.
    pub async fn get_balance(&self, address: AccountAddress) -> Result<u64, MovementError>;
    
    /// Get account sequence number.
    pub async fn get_sequence_number(&self, address: AccountAddress) -> Result<u64, MovementError>;
    
    /// Get ledger info.
    pub async fn ledger_info(&self) -> Result<LedgerInfo, MovementError>;
    
    /// Submit a transaction and wait for confirmation.
    pub async fn submit_and_wait(
        &self,
        signed_txn: &SignedTransaction,
        timeout: Option<Duration>,
    ) -> Result<TransactionResponse, MovementError>;
    
    /// Sign, submit, and wait for a transaction.
    pub async fn sign_submit_and_wait(
        &self,
        account: &impl Account,
        payload: TransactionPayload,
        options: Option<TransactionOptions>,
    ) -> Result<TransactionResponse, MovementError>;
    
    /// Call a view function.
    pub async fn view(
        &self,
        function: &str,
        type_args: Vec<String>,
        args: Vec<serde_json::Value>,
    ) -> Result<Vec<serde_json::Value>, MovementError>;
    
    /// Fund an account (testnet/devnet only).
    #[cfg(feature = "faucet")]
    pub async fn fund_account(
        &self,
        address: AccountAddress,
        amount: u64,
    ) -> Result<(), MovementError>;
    
    /// Create and fund a new account.
    #[cfg(feature = "faucet")]
    pub async fn create_funded_account(&self, amount: u64) -> Result<Ed25519Account, MovementError>;
}
```

### MovementFullnodeClient

```rust
/// Client for Movement fullnode REST API.
#[derive(Clone)]
pub struct MovementFullnodeClient {
    base_url: Url,
    http_client: reqwest::Client,
}

impl MovementFullnodeClient {
    /// Create a new fullnode client.
    pub fn new(base_url: impl Into<Url>) -> Self;
    
    // === Ledger Info ===
    
    /// Get ledger information.
    pub async fn get_ledger_info(&self) -> Result<Response<LedgerInfo>, MovementError>;
    
    // === Account Queries ===
    
    /// Get account information.
    pub async fn get_account(
        &self,
        address: AccountAddress,
    ) -> Result<Response<AccountData>, MovementError>;
    
    /// Get account resources.
    pub async fn get_account_resources(
        &self,
        address: AccountAddress,
    ) -> Result<Response<Vec<AccountResource>>, MovementError>;
    
    /// Get a specific resource.
    pub async fn get_account_resource(
        &self,
        address: AccountAddress,
        resource_type: &str,
    ) -> Result<Response<AccountResource>, MovementError>;
    
    /// Get account modules.
    pub async fn get_account_modules(
        &self,
        address: AccountAddress,
    ) -> Result<Response<Vec<MoveModule>>, MovementError>;
    
    /// Get a specific module.
    pub async fn get_account_module(
        &self,
        address: AccountAddress,
        module_name: &str,
    ) -> Result<Response<MoveModule>, MovementError>;
    
    // === Transaction Queries ===
    
    /// Get transaction by hash.
    pub async fn get_transaction_by_hash(
        &self,
        hash: &str,
    ) -> Result<Response<serde_json::Value>, MovementError>;
    
    /// Get transaction by version.
    pub async fn get_transaction_by_version(
        &self,
        version: u64,
    ) -> Result<Response<serde_json::Value>, MovementError>;
    
    /// Get account transactions.
    pub async fn get_account_transactions(
        &self,
        address: AccountAddress,
        start: Option<u64>,
        limit: Option<u64>,
    ) -> Result<Response<Vec<serde_json::Value>>, MovementError>;
    
    // === Block Queries ===
    
    /// Get block by height.
    pub async fn get_block_by_height(
        &self,
        height: u64,
        with_transactions: bool,
    ) -> Result<Response<Block>, MovementError>;
    
    /// Get block by version.
    pub async fn get_block_by_version(
        &self,
        version: u64,
        with_transactions: bool,
    ) -> Result<Response<Block>, MovementError>;
    
    // === Events ===
    
    /// Get events by event handle.
    pub async fn get_events_by_event_handle(
        &self,
        address: AccountAddress,
        event_handle_struct: &str,
        field_name: &str,
        start: Option<u64>,
        limit: Option<u64>,
    ) -> Result<Response<Vec<Event>>, MovementError>;
    
    // === Transaction Submission ===
    
    /// Submit a signed transaction.
    pub async fn submit_transaction(
        &self,
        signed_txn: &SignedTransaction,
    ) -> Result<Response<PendingTransaction>, MovementError>;
    
    /// Simulate a transaction.
    pub async fn simulate_transaction(
        &self,
        signed_txn: &SignedTransaction,
    ) -> Result<Response<Vec<SimulationResult>>, MovementError>;
    
    /// Wait for transaction confirmation.
    pub async fn wait_for_transaction(
        &self,
        hash: &str,
        timeout: Option<Duration>,
    ) -> Result<Response<serde_json::Value>, MovementError>;
    
    // === View Functions ===
    
    /// Execute a view function.
    pub async fn view_function(
        &self,
        request: ViewRequest,
    ) -> Result<Response<Vec<serde_json::Value>>, MovementError>;
    
    // === Gas Estimation ===
    
    /// Estimate gas price.
    pub async fn estimate_gas_price(&self) -> Result<Response<GasEstimate>, MovementError>;
}
```

### MovementFaucetClient (Feature: `faucet`)

```rust
/// Client for Movement faucet service.
#[cfg(feature = "faucet")]
pub struct MovementFaucetClient {
    base_url: Url,
    http_client: reqwest::Client,
}

impl MovementFaucetClient {
    /// Create a new faucet client.
    pub fn new(base_url: impl Into<Url>) -> Self;
    
    /// Fund an account with test tokens.
    pub async fn fund(
        &self,
        address: AccountAddress,
        amount: u64,
    ) -> Result<Vec<String>, MovementError>;
}
```

### MovementIndexerClient (Feature: `indexer`)

```rust
/// Client for Movement indexer GraphQL API.
#[cfg(feature = "indexer")]
pub struct MovementIndexerClient {
    base_url: Url,
    http_client: reqwest::Client,
}

impl MovementIndexerClient {
    /// Create a new indexer client.
    pub fn new(base_url: impl Into<Url>) -> Self;
    
    /// Execute a GraphQL query.
    pub async fn query<T: DeserializeOwned>(
        &self,
        query: &str,
        variables: serde_json::Value,
    ) -> Result<T, MovementError>;
    
    /// Get account tokens (NFTs).
    pub async fn get_account_tokens(
        &self,
        address: AccountAddress,
    ) -> Result<Vec<TokenData>, MovementError>;
    
    /// Get fungible asset balances.
    pub async fn get_fungible_asset_balances(
        &self,
        address: AccountAddress,
    ) -> Result<Vec<FungibleAssetBalance>, MovementError>;
    
    /// Get account transactions.
    pub async fn get_account_transactions(
        &self,
        address: AccountAddress,
        limit: Option<u64>,
        offset: Option<u64>,
    ) -> Result<Vec<IndexerTransaction>, MovementError>;
}
```

### Response Types

```rust
/// API response wrapper with metadata.
#[derive(Debug)]
pub struct Response<T> {
    /// Response data.
    pub data: T,
    /// Ledger state from response headers.
    pub state: LedgerState,
}

/// Ledger state from response headers.
#[derive(Debug, Clone)]
pub struct LedgerState {
    pub chain_id: ChainId,
    pub epoch: u64,
    pub ledger_version: u64,
    pub oldest_ledger_version: u64,
    pub ledger_timestamp: u64,
    pub block_height: u64,
    pub oldest_block_height: u64,
}

/// Pending transaction response.
#[derive(Debug, Deserialize)]
pub struct PendingTransaction {
    pub hash: String,
}

/// Gas estimation response.
#[derive(Debug, Deserialize)]
pub struct GasEstimate {
    pub gas_estimate: u64,
    pub deprioritized_gas_estimate: Option<u64>,
    pub prioritized_gas_estimate: Option<u64>,
}
```

---

## Implementation Details

### Request Flow

```
User Request
    ↓
Build URL + Headers
    ↓
HTTP Request (reqwest)
    ↓
Parse Headers (ledger state)
    ↓
Parse Body (JSON/BCS)
    ↓
Return Response<T>
```

### Content Types

| Endpoint | Request Type | Response Type |
|----------|-------------|---------------|
| GET endpoints | N/A | `application/json` |
| Submit transaction | `application/x.movement.signed_transaction+bcs` | `application/json` |
| Simulate transaction | `application/x.movement.signed_transaction+bcs` | `application/json` |
| View function | `application/json` | `application/json` |

### Error Response Handling

```rust
// API error response format
#[derive(Deserialize)]
struct ApiError {
    message: String,
    error_code: String,
    vm_error_code: Option<u64>,
}

// Convert to MovementError
impl From<ApiError> for MovementError {
    fn from(api_error: ApiError) -> Self {
        MovementError::Api {
            message: api_error.message,
            code: api_error.error_code,
            vm_error: api_error.vm_error_code,
        }
    }
}
```

### Retry Strategy

```rust
// Default retry configuration
const MAX_RETRIES: u32 = 3;
const RETRY_DELAY_MS: u64 = 100;

// Retryable errors
fn is_retryable(error: &MovementError) -> bool {
    matches!(error, 
        MovementError::Network(_) |
        MovementError::Timeout |
        MovementError::Api { code, .. } if code == "rate_limited"
    )
}
```

---

## Usage Examples

### Basic Usage

```rust
use movement_sdk::{Movement, MovementConfig};

// Connect to testnet
let movement = Movement::new(MovementConfig::testnet()).await?;

// Get balance
let balance = movement.get_balance(address).await?;
println!("Balance: {} APT", balance as f64 / 100_000_000.0);
```

### View Function Call

```rust
// Call 0x1::coin::balance<0x1::aptos_coin::AptosCoin>
let result = movement.view(
    "0x1::coin::balance",
    vec!["0x1::aptos_coin::AptosCoin".to_string()],
    vec![serde_json::json!(address.to_hex())],
).await?;
```

### Submit Transaction

```rust
let payload = EntryFunction::apt_transfer(recipient, amount)?;

// Sign, submit, and wait
let result = movement.sign_submit_and_wait(
    &account,
    payload.into(),
    None,
).await?;

println!("Transaction hash: {}", result.hash);
```

### Using Fullnode Client Directly

```rust
let client = movement.fullnode();

// Get resources
let resources = client.get_account_resources(address).await?;
for resource in resources.data {
    println!("{}: {:?}", resource.typ, resource.data);
}

// Get events
let events = client.get_events_by_event_handle(
    address,
    "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>",
    "deposit_events",
    Some(0),
    Some(10),
).await?;
```

---

## Error Handling

| Error | Cause |
|-------|-------|
| `Network` | Connection failed |
| `Timeout` | Request timed out |
| `Api` | Server returned error |
| `NotFound` | Resource not found (404) |
| `InvalidResponse` | Could not parse response |
| `Serialization` | Request serialization failed |

### Error Context

```rust
// Errors include context
match movement.get_balance(address).await {
    Ok(balance) => println!("Balance: {}", balance),
    Err(MovementError::NotFound { resource, .. }) => {
        println!("Account {} not found", address);
    }
    Err(e) => println!("Error: {}", e),
}
```

---

## Testing Requirements

### Unit Tests (Mocked)

```rust
#[tokio::test]
async fn test_get_balance_parses_response() {
    let mock_server = MockServer::start().await;
    
    Mock::given(method("GET"))
        .and(path_regex(r"/v1/accounts/.*/resource/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "type": "0x1::coin::CoinStore<0x1::aptos_coin::AptosCoin>",
            "data": {
                "coin": { "value": "100000000" }
            }
        })))
        .mount(&mock_server)
        .await;
    
    let client = MovementFullnodeClient::new(mock_server.uri());
    let resource = client.get_account_resource(addr, "...").await.unwrap();
    // ... assert
}
```

### Integration Tests (Testnet)

```rust
#[tokio::test]
#[ignore] // Run with --ignored
async fn test_real_testnet_connection() {
    let movement = Movement::new(MovementConfig::testnet()).await.unwrap();
    let info = movement.ledger_info().await.unwrap();
    assert!(info.ledger_version() > 0);
}
```

---

## Security Considerations

1. **HTTPS Only**: All production endpoints use HTTPS
2. **No Sensitive Data in URLs**: Use POST for sensitive data
3. **Timeout Protection**: Always set request timeouts
4. **Rate Limiting**: Respect server rate limits

---

## Dependencies

### External Crates
- `reqwest`: HTTP client
- `serde_json`: JSON parsing
- `url`: URL handling
- `tokio`: Async runtime

### Internal Modules
- `types`: Core types
- `transaction`: Transaction types
- `error`: Error types

---

## Open Questions

1. ~~Should we support WebSocket?~~ (Decided: Future feature)
2. ~~Should we cache ledger state?~~ (Decided: User responsibility)
3. Should we add connection pooling? (Decided: Use reqwest defaults)

