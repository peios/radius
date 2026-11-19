//! Peios adapters. These never impersonate an administrator or elevate writes.
pub mod accounting;
pub mod configuration;
pub mod control;
pub mod credentials;
pub mod diagnostics;
pub mod dynamic;
mod dynamic_commands;
#[cfg(test)]
mod dynamic_tests;
pub mod operations;
pub mod registry;
pub mod service;
