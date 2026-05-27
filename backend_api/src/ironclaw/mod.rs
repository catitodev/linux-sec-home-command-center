// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

//! IronClaw AI Assistant subsystem.
//!
//! Provides natural language interaction with the Linux Security Home Command Center
//! through local LLM inference (Ollama), external providers, or rule-based fallback.

pub mod actions;
pub mod context;
pub mod history;
pub mod inference;
pub mod intent;
