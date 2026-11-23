//! Calls to Azure, always made as the signed-in user via on-behalf-of.

pub mod access_review;
pub mod audit;
pub mod audit_across;
pub mod audit_keyring;
pub mod authz;
pub mod certs;
pub mod client;
pub mod defender;
pub mod fanout;
pub mod graph;
pub mod keys;
pub mod paging;
pub mod pim;
pub mod secrets;
pub mod share;
pub mod token;
pub mod used_by;
pub mod vaults;

pub use client::{AzureClient, AzureError};
pub use token::{Resource, TokenBroker, TokenError};
