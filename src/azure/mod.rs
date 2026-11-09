//! Calls to Azure, always made as the signed-in user via on-behalf-of.

pub mod certs;
pub mod client;
pub mod secrets;
pub mod token;
pub mod vaults;

pub use client::{AzureClient, AzureError};
pub use token::{AccessToken, Resource, TokenBroker, TokenError};
