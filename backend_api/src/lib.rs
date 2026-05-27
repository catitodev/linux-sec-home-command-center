// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Backend API library for the Linux Security Home Command Center.
//!
//! This crate contains the business logic, API routing, tool orchestration,
//! event processing, and LLM integration modules.

pub mod api;
pub mod auth;
pub mod correlator;
pub mod db;
pub mod tools;

/// Re-export shared types for convenience.
pub use shared;
