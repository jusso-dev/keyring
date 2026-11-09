//! Calls to Azure, always made as the signed-in user via on-behalf-of.

pub mod client;
pub mod token;

pub use client::{AzureClient, AzureError};
pub use token::{AccessToken, Resource, TokenBroker, TokenError};
