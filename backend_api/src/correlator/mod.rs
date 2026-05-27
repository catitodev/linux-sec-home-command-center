// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! Event correlation subsystem for the Linux Security Home Command Center.
//!
//! This module provides:
//! - Event normalization from tool-specific formats to a common schema
//! - Correlation engine with sliding window analysis
//! - Automated response engine with rate limiting
//! - Process and network baseline anomaly detection

pub mod baseline;
pub mod engine;
pub mod normalizer;
pub mod response;
