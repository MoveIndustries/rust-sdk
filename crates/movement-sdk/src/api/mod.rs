//! API clients for the Movement blockchain.
//!
//! This module provides clients for interacting with the Movement network:
//!
//! - [`FullnodeClient`] - REST API client for fullnode operations
//! - [`FaucetClient`] - Client for funding accounts on testnets (feature-gated)
//! - [`IndexerClient`] - GraphQL client for indexed data (feature-gated)

pub mod fullnode;
pub mod response;

#[cfg(feature = "faucet")]
mod faucet;

#[cfg(feature = "indexer")]
mod indexer;

pub use fullnode::FullnodeClient;
pub use response::{MovementResponse, GasEstimation, LedgerInfo, PendingTransaction};

#[cfg(feature = "faucet")]
pub use faucet::FaucetClient;

#[cfg(feature = "indexer")]
pub use indexer::{
    CoinActivity, CoinBalance, Collection, CollectionData, Event, FungibleAssetBalance,
    FungibleAssetMetadata, IndexerClient, Page, PaginationParams, ProcessorStatus, TokenBalance,
    TokenData, Transaction,
};
