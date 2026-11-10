//! Calls to Azure, always made as the signed-in user via on-behalf-of.

pub mod audit;
pub mod certs;
pub mod client;
pub mod keys;
pub mod paging;
pub mod secrets;
pub mod token;
pub mod vaults;

pub use client::{AzureClient, AzureError};
pub use token::{Resource, TokenBroker, TokenError};
