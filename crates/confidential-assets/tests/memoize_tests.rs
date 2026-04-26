// Parity with ts-sdk/confidential-assets memoize helpers
use confidential_assets::{
    clear_cache, get_available_balance_cache_key, get_cache, get_pending_balance_cache_key,
    memoize_async_run, set_cache,
};

#[test]
fn cache_key_format_matches_ts_pending() {
    let k = get_pending_balance_cache_key("0x1", "0x2", "mainnet");
    assert_eq!(k, "0x1-pending-encrypted-balance-for-0x2-mainnet");
}

#[test]
fn cache_key_format_matches_ts_available() {
    let k = get_available_balance_cache_key("0xaa", "0xbb", "testnet");
    assert_eq!(k, "0xaa-available-encrypted-balance-for-0xbb-testnet");
}

#[tokio::test]
async fn memoize_async_run_caches_value() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    let key = "memoize-async-test-key".to_string();
    clear_cache(&key);
    let calls = Arc::new(AtomicU32::new(0));
    let c1 = calls.clone();
    let v1 = memoize_async_run(
        || {
            let c = c1.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                42u32
            }
        },
        key.clone(),
        None,
        true,
    )
    .await;
    let c2 = calls.clone();
    let v2 = memoize_async_run(
        || {
            let c = c2.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                99u32
            }
        },
        key.clone(),
        None,
        true,
    )
    .await;
    assert_eq!(v1, 42);
    assert_eq!(v2, 42);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    clear_cache(&key);
}

#[test]
fn set_and_get_cache_roundtrip() {
    let k = "unit-test-cache-key".to_string();
    clear_cache(&k);
    set_cache(k.clone(), vec![1u8, 2, 3]);
    let v: Vec<u8> = get_cache(&k, None).expect("cached");
    assert_eq!(v, vec![1, 2, 3]);
    clear_cache(&k);
}
