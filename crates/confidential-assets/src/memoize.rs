// Copyright © Move Industries
// SPDX-License-Identifier: Apache-2.0

//! TTL cache and memoization helpers (parity with TS SDK `utils/memoize.ts`).

use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

struct Entry {
    at: Instant,
    value: Arc<dyn Any + Send + Sync>,
}

static CACHE: OnceLock<Mutex<HashMap<String, Entry>>> = OnceLock::new();

fn global() -> &'static Mutex<HashMap<String, Entry>> {
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Read a cached value if present and within TTL.
pub fn get_cache<T: Clone + Send + Sync + 'static>(key: &str, ttl_ms: Option<u64>) -> Option<T> {
    let map = global().lock().ok()?;
    let e = map.get(key)?;
    if let Some(ms) = ttl_ms
        && e.at.elapsed() > Duration::from_millis(ms)
    {
        return None;
    }
    e.value.downcast_ref::<T>().cloned()
}

/// Insert or replace a cache entry.
pub fn set_cache<T: Send + Sync + 'static>(key: String, value: T) {
    let mut map = global().lock().expect("memoize cache mutex poisoned");
    map.insert(
        key,
        Entry {
            at: Instant::now(),
            value: Arc::new(value),
        },
    );
}

/// Remove one key.
pub fn clear_cache(key: &str) {
    let mut map = global().lock().expect("memoize cache mutex poisoned");
    map.remove(key);
}

/// Cache keys matching the TS SDK string format (`address` and `token` are display strings, e.g. hex).
pub fn get_pending_balance_cache_key(address: &str, token_address: &str, network: &str) -> String {
    format!("{address}-pending-encrypted-balance-for-{token_address}-{network}")
}

pub fn get_available_balance_cache_key(
    address: &str,
    token_address: &str,
    network: &str,
) -> String {
    format!("{address}-available-encrypted-balance-for-{token_address}-{network}")
}

pub fn get_encryption_key_cache_key(address: &str, token_address: &str, network: &str) -> String {
    format!("{address}-encryption-key-for-{token_address}-{network}")
}

/// Clear pending + available balance cache entries for an account/token/network.
pub fn clear_balance_cache(address: &str, token_address: &str, network: &str) {
    clear_cache(&get_pending_balance_cache_key(
        address,
        token_address,
        network,
    ));
    clear_cache(&get_available_balance_cache_key(
        address,
        token_address,
        network,
    ));
}

/// Clear encryption key cache for an account/token/network.
pub fn clear_encryption_key_cache(address: &str, token_address: &str, network: &str) {
    clear_cache(&get_encryption_key_cache_key(
        address,
        token_address,
        network,
    ));
}

/// Memoize a synchronous function (TS `memoize`): first call runs `func` and caches under `key`.
pub fn memoize<F, T>(func: F, key: String, ttl_ms: Option<u64>) -> impl Fn() -> T
where
    F: Fn() -> T + Clone,
    T: Clone + Send + Sync + 'static,
{
    move || {
        if let Some(v) = get_cache::<T>(&key, ttl_ms) {
            return v;
        }
        let out = func();
        set_cache(key.clone(), out.clone());
        out
    }
}

/// Async memoized execution (TS `memoizeAsync`): caches the result of `func().await` under `key`.
pub async fn memoize_async_run<F, Fut, T>(
    func: F,
    key: String,
    ttl_ms: Option<u64>,
    use_cached_value: bool,
) -> T
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
    T: Clone + Send + Sync + 'static,
{
    if use_cached_value && let Some(v) = get_cache::<T>(&key, ttl_ms) {
        return v;
    }
    let out = func().await;
    set_cache(key, out.clone());
    out
}
