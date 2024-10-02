//! This crate provides an implementation of garbled circuit protocols to facilitate MPC.

// #![deny(missing_docs, unreachable_pub, unused_must_use)]
// #![deny(clippy::all)]
// #![forbid(unsafe_code)]

pub(crate) mod evaluator;
pub(crate) mod generator;
pub mod protocol;
pub(crate) mod store;
