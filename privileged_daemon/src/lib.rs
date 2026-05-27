// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Privileged Daemon library for the Linux Security Home Command Center.
//!
//! This crate contains the D-Bus service implementation, operation whitelist
//! enforcement, integrity verification, and privileged tool management modules.

pub mod dbus_service;
pub mod integrity;
pub mod integrity_hashes;
pub mod service;
pub mod whitelist;

/// Re-export shared types for convenience.
pub use shared;
