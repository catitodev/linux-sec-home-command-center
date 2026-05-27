// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Shared library for the Linux Security Home Command Center.
//!
//! Contains common types, error definitions, D-Bus interface definitions,
//! and configuration structures used by both `backend_api` and `privileged_daemon`.

pub mod config;
pub mod dbus;
pub mod distro;
pub mod errors;
pub mod exec;
pub mod logging;
pub mod types;
