// Copyright 2024-2026 catitodev
// Licensed under the Apache License, Version 2.0
// SPDX-License-Identifier: Apache-2.0

/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{html,js,svelte,ts}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Security state colors
        'sec-safe': '#22c55e',
        'sec-warning': '#eab308',
        'sec-danger': '#ef4444',
        'sec-critical': '#dc2626',
        // Dark theme palette
        'surface-primary': '#0f172a',
        'surface-secondary': '#1e293b',
        'surface-tertiary': '#334155',
        'text-primary': '#f8fafc',
        'text-secondary': '#94a3b8',
        'text-muted': '#64748b',
        // Paranoia mode accent
        'paranoia': '#b91c1c',
        'paranoia-glow': '#fca5a5',
      },
      backdropBlur: {
        'glass': '12px',
      },
      boxShadow: {
        'glass': '0 8px 32px 0 rgba(31, 38, 135, 0.37)',
      },
    },
  },
  plugins: [],
};
