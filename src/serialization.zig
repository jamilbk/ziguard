// Copyright (c) 2024 Ziguard contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
//
// WireGuard key serialization (base64 / hex).
// Ported from boringtun (Cloudflare, Inc.; Firezone fork)

const std = @import("std");

pub const KeyBytes = [32]u8;

pub const KeyParseError = error{
    IllegalCharacter,
    IllegalKeySize,
    InvalidBase64,
};

/// Parse a 32-byte key from a hex (64 chars) or base64 (43–44 chars) encoded string.
pub fn parseKey(s: []const u8) KeyParseError!KeyBytes {
    switch (s.len) {
        64 => {
            // Hex
            var key: KeyBytes = undefined;
            for (0..32) |i| {
                key[i] = std.fmt.parseUnsigned(u8, s[i * 2 ..][0..2], 16) catch
                    return error.IllegalCharacter;
            }
            return key;
        },
        43, 44 => {
            // Base64
            var key: KeyBytes = undefined;
            const decoder = std.base64.standard.Decoder;
            const decoded_len = decoder.calcSizeForSlice(s) catch return error.InvalidBase64;
            if (decoded_len != 32) return error.IllegalKeySize;
            decoder.decode(&key, s) catch return error.InvalidBase64;
            return key;
        },
        else => return error.IllegalKeySize,
    }
}

/// Encode a 32-byte key as base64 (44 chars with padding).
pub fn keyToBase64(key: *const KeyBytes) [44]u8 {
    var buf: [44]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&buf, key);
    return buf;
}

/// Encode a 32-byte key as lowercase hex (64 chars).
pub fn keyToHex(key: *const KeyBytes) [64]u8 {
    var buf: [64]u8 = undefined;
    const hex = "0123456789abcdef";
    for (key, 0..) |byte, i| {
        buf[i * 2] = hex[byte >> 4];
        buf[i * 2 + 1] = hex[byte & 0x0f];
    }
    return buf;
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "parse hex key" {
    const hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const key = try parseKey(hex);
    try testing.expectEqual(@as(u8, 0x01), key[0]);
    try testing.expectEqual(@as(u8, 0x23), key[1]);
    try testing.expectEqual(@as(u8, 0xef), key[31]);
}

test "parse base64 key" {
    // Encode a known key to base64, then parse it back
    const original = [_]u8{0x42} ** 32;
    const b64 = keyToBase64(&original);
    const parsed = try parseKey(&b64);
    try testing.expectEqualSlices(u8, &original, &parsed);
}

test "round-trip hex" {
    const original = [_]u8{0xAB} ** 32;
    const hex = keyToHex(&original);
    const parsed = try parseKey(&hex);
    try testing.expectEqualSlices(u8, &original, &parsed);
}

test "invalid key size" {
    try testing.expectError(error.IllegalKeySize, parseKey("too_short"));
}

test "invalid hex character" {
    const bad_hex = "zz23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    try testing.expectError(error.IllegalCharacter, parseKey(bad_hex));
}
