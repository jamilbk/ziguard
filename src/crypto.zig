// Copyright (c) 2024 Ziguard contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
//
// Thin crypto wrapper mapping boringtun's crypto calls to Zig std.
// All WireGuard cryptographic primitives are provided by the Zig standard library.

const std = @import("std");

pub const Blake2s256 = std.crypto.hash.blake2.Blake2s256;
pub const Blake2s128 = std.crypto.hash.blake2.Blake2s128;
pub const Blake2s192 = std.crypto.hash.blake2.Blake2s(192);
pub const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
pub const XChaCha20Poly1305 = std.crypto.aead.chacha_poly.XChaCha20Poly1305;
pub const X25519 = std.crypto.dh.X25519;
pub const HmacBlake2s256 = std.crypto.auth.hmac.Hmac(Blake2s256);

const tag_length = ChaCha20Poly1305.tag_length; // 16

/// BLAKE2s(data1 || data2) -> 32 bytes
pub fn b2sHash(data1: []const u8, data2: []const u8) [32]u8 {
    var hasher = Blake2s256.init(.{});
    hasher.update(data1);
    hasher.update(data2);
    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}

/// RFC 2401 HMAC-BLAKE2s(key, data1) -> 32 bytes
/// Note: This is HMAC using BLAKE2s as the hash, NOT keyed BLAKE2s.
pub fn b2sHmac(key: []const u8, data1: []const u8) [32]u8 {
    var hmac = HmacBlake2s256.init(key);
    hmac.update(data1);
    var out: [32]u8 = undefined;
    hmac.final(&out);
    return out;
}

/// RFC 2401 HMAC-BLAKE2s(key, data1 || data2) -> 32 bytes
pub fn b2sHmac2(key: []const u8, data1: []const u8, data2: []const u8) [32]u8 {
    var hmac = HmacBlake2s256.init(key);
    hmac.update(data1);
    hmac.update(data2);
    var out: [32]u8 = undefined;
    hmac.final(&out);
    return out;
}

/// Keyed BLAKE2s MAC with 16-byte (128-bit) output
pub fn b2sKeyedMac16(key: []const u8, data1: []const u8) [16]u8 {
    var hasher = Blake2s128.init(.{ .key = key });
    hasher.update(data1);
    var out: [16]u8 = undefined;
    hasher.final(&out);
    return out;
}

/// Keyed BLAKE2s MAC with 16-byte output over data1 || data2
pub fn b2sKeyedMac16_2(key: []const u8, data1: []const u8, data2: []const u8) [16]u8 {
    var hasher = Blake2s128.init(.{ .key = key });
    hasher.update(data1);
    hasher.update(data2);
    var out: [16]u8 = undefined;
    hasher.final(&out);
    return out;
}

/// Keyed BLAKE2s MAC with 24-byte (192-bit) output
pub fn b2sMac24(key: []const u8, data1: []const u8) [24]u8 {
    var hasher = Blake2s192.init(.{ .key = key });
    hasher.update(data1);
    var out: [24]u8 = undefined;
    hasher.final(&out);
    return out;
}

/// Build WireGuard nonce: 4 zero bytes + 8-byte LE counter
fn buildNonce(counter: u64) [12]u8 {
    var nonce = [_]u8{0} ** 12;
    const counter_bytes = std.mem.toBytes(std.mem.nativeToLittle(u64, counter));
    @memcpy(nonce[4..12], &counter_bytes);
    return nonce;
}

/// ChaCha20Poly1305 AEAD seal.
/// Encrypts `data` with associated data `aad`, using the WireGuard nonce format.
/// `dst` must be at least data.len + 16 bytes (ciphertext + tag).
pub fn aeadChaCha20Seal(dst: []u8, key: [32]u8, counter: u64, data: []const u8, aad: []const u8) void {
    std.debug.assert(dst.len >= data.len + tag_length);
    const nonce = buildNonce(counter);
    ChaCha20Poly1305.encrypt(dst[0..data.len], dst[data.len..][0..tag_length], data, aad, nonce, key);
}

/// ChaCha20Poly1305 AEAD seal with a raw 12-byte nonce.
pub fn aeadChaCha20SealInner(dst: []u8, key: [32]u8, nonce: [12]u8, data: []const u8, aad: []const u8) void {
    std.debug.assert(dst.len >= data.len + tag_length);
    ChaCha20Poly1305.encrypt(dst[0..data.len], dst[data.len..][0..tag_length], data, aad, nonce, key);
}

/// ChaCha20Poly1305 AEAD open.
/// Decrypts `data` (ciphertext + 16-byte tag) into `dst`.
/// `dst` must be at least data.len - 16 bytes.
/// Returns error.InvalidAeadTag on authentication failure.
pub fn aeadChaCha20Open(dst: []u8, key: [32]u8, counter: u64, data: []const u8, aad: []const u8) error{InvalidAeadTag}!void {
    if (data.len < tag_length) return error.InvalidAeadTag;
    const ct_len = data.len - tag_length;
    std.debug.assert(dst.len >= ct_len);
    const nonce = buildNonce(counter);
    const ciphertext = data[0..ct_len];
    const tag: [tag_length]u8 = data[ct_len..][0..tag_length].*;
    ChaCha20Poly1305.decrypt(dst[0..ct_len], ciphertext, tag, aad, nonce, key) catch return error.InvalidAeadTag;
}

/// ChaCha20Poly1305 AEAD open with a raw 12-byte nonce.
pub fn aeadChaCha20OpenInner(dst: []u8, key: [32]u8, nonce: [12]u8, data: []const u8, aad: []const u8) error{InvalidAeadTag}!void {
    if (data.len < tag_length) return error.InvalidAeadTag;
    const ct_len = data.len - tag_length;
    std.debug.assert(dst.len >= ct_len);
    const ciphertext = data[0..ct_len];
    const tag: [tag_length]u8 = data[ct_len..][0..tag_length].*;
    ChaCha20Poly1305.decrypt(dst[0..ct_len], ciphertext, tag, aad, nonce, key) catch return error.InvalidAeadTag;
}

/// XChaCha20Poly1305 AEAD seal (used for cookie replies).
/// `dst` must be at least data.len + 16 bytes.
pub fn xaeadSeal(dst: []u8, key: [32]u8, nonce: [24]u8, data: []const u8, aad: []const u8) void {
    std.debug.assert(dst.len >= data.len + tag_length);
    XChaCha20Poly1305.encrypt(dst[0..data.len], dst[data.len..][0..tag_length], data, aad, nonce, key);
}

/// XChaCha20Poly1305 AEAD open (used for cookie replies).
/// `data` is ciphertext + 16-byte tag, decrypted into `dst`.
pub fn xaeadOpen(dst: []u8, key: [32]u8, nonce: [24]u8, data: []const u8, aad: []const u8) error{InvalidAeadTag}!void {
    if (data.len < tag_length) return error.InvalidAeadTag;
    const ct_len = data.len - tag_length;
    std.debug.assert(dst.len >= ct_len);
    const ciphertext = data[0..ct_len];
    const tag: [tag_length]u8 = data[ct_len..][0..tag_length].*;
    XChaCha20Poly1305.decrypt(dst[0..ct_len], ciphertext, tag, aad, nonce, key) catch return error.InvalidAeadTag;
}

/// X25519 Diffie-Hellman key agreement.
pub fn x25519(secret_key: [32]u8, public_key: [32]u8) error{IdentityElement}![32]u8 {
    return X25519.scalarmult(secret_key, public_key) catch return error.IdentityElement;
}

/// Compute X25519 public key from a secret key.
pub fn x25519PublicKey(secret_key: [32]u8) error{IdentityElement}![32]u8 {
    return X25519.recoverPublicKey(secret_key) catch return error.IdentityElement;
}

/// Generate a random X25519 key pair.
pub fn x25519KeyPairGenerate() X25519.KeyPair {
    return X25519.KeyPair.generate();
}

/// Constant-time equality comparison.
pub fn constantTimeEq(comptime T: type, a: T, b: T) bool {
    return std.crypto.timing_safe.eql(T, a, b);
}

/// Fill a buffer with cryptographically secure random bytes.
pub fn randomBytes(buf: []u8) void {
    std.crypto.random.bytes(buf);
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "b2sHash basic" {
    // BLAKE2s("") should match known digest
    const result = b2sHash("", "");
    // BLAKE2s-256 of empty input
    const expected = [_]u8{
        0x69, 0x21, 0x7a, 0x30, 0x79, 0x90, 0x80, 0x94,
        0xe1, 0x11, 0x21, 0xd0, 0x42, 0x35, 0x4a, 0x7c,
        0x1f, 0x55, 0xb6, 0x48, 0x2c, 0xa1, 0xa5, 0x1e,
        0x1b, 0x25, 0x0d, 0xfd, 0x1e, 0xd0, 0xee, 0xf9,
    };
    try testing.expectEqualSlices(u8, &expected, &result);
}

test "b2sHash concatenation" {
    // b2sHash(a, b) should equal BLAKE2s(a || b)
    const result = b2sHash("hello", "world");
    var hasher = Blake2s256.init(.{});
    hasher.update("hello");
    hasher.update("world");
    var expected: [32]u8 = undefined;
    hasher.final(&expected);
    try testing.expectEqualSlices(u8, &expected, &result);
}

test "b2sHmac basic" {
    // HMAC-BLAKE2s with known key and data
    const result = b2sHmac("key", "data");
    var hmac = HmacBlake2s256.init("key");
    hmac.update("data");
    var expected: [32]u8 = undefined;
    hmac.final(&expected);
    try testing.expectEqualSlices(u8, &expected, &result);
}

test "b2sHmac2 matches concatenated update" {
    const result = b2sHmac2("key", "hello", "world");
    var hmac = HmacBlake2s256.init("key");
    hmac.update("hello");
    hmac.update("world");
    var expected: [32]u8 = undefined;
    hmac.final(&expected);
    try testing.expectEqualSlices(u8, &expected, &result);
}

test "b2sKeyedMac16 produces 16 bytes" {
    const result = b2sKeyedMac16("0123456789abcdef0123456789abcdef", "test data");
    try testing.expectEqual(@as(usize, 16), result.len);
}

test "b2sMac24 produces 24 bytes" {
    const result = b2sMac24("0123456789abcdef0123456789abcdef", "test data");
    try testing.expectEqual(@as(usize, 24), result.len);
}

test "AEAD ChaCha20Poly1305 round-trip" {
    const key = [_]u8{0x42} ** 32;
    const plaintext = "Hello, WireGuard!";
    const aad = "additional data";

    var ciphertext: [plaintext.len + tag_length]u8 = undefined;
    aeadChaCha20Seal(&ciphertext, key, 1, plaintext, aad);

    var decrypted: [plaintext.len]u8 = undefined;
    try aeadChaCha20Open(&decrypted, key, 1, &ciphertext, aad);
    try testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "AEAD ChaCha20Poly1305 wrong key fails" {
    const key = [_]u8{0x42} ** 32;
    const wrong_key = [_]u8{0x43} ** 32;
    const plaintext = "Hello, WireGuard!";

    var ciphertext: [plaintext.len + tag_length]u8 = undefined;
    aeadChaCha20Seal(&ciphertext, key, 0, plaintext, "");

    var decrypted: [plaintext.len]u8 = undefined;
    try testing.expectError(error.InvalidAeadTag, aeadChaCha20Open(&decrypted, wrong_key, 0, &ciphertext, ""));
}

test "AEAD ChaCha20Poly1305 wrong counter fails" {
    const key = [_]u8{0x42} ** 32;
    const plaintext = "Hello, WireGuard!";

    var ciphertext: [plaintext.len + tag_length]u8 = undefined;
    aeadChaCha20Seal(&ciphertext, key, 0, plaintext, "");

    var decrypted: [plaintext.len]u8 = undefined;
    try testing.expectError(error.InvalidAeadTag, aeadChaCha20Open(&decrypted, key, 1, &ciphertext, ""));
}

test "XChaCha20Poly1305 round-trip" {
    const key = [_]u8{0x42} ** 32;
    const nonce = [_]u8{0x24} ** 24;
    const plaintext = "cookie data";
    const aad = "";

    var ciphertext: [plaintext.len + tag_length]u8 = undefined;
    xaeadSeal(&ciphertext, key, nonce, plaintext, aad);

    var decrypted: [plaintext.len]u8 = undefined;
    try xaeadOpen(&decrypted, key, nonce, &ciphertext, aad);
    try testing.expectEqualSlices(u8, plaintext, &decrypted);
}

test "X25519 key agreement" {
    const alice = x25519KeyPairGenerate();
    const bob = x25519KeyPairGenerate();

    const shared_alice = try x25519(alice.secret_key, bob.public_key);
    const shared_bob = try x25519(bob.secret_key, alice.public_key);
    try testing.expectEqualSlices(u8, &shared_alice, &shared_bob);
}

test "X25519 public key derivation" {
    const kp = x25519KeyPairGenerate();
    const derived = try x25519PublicKey(kp.secret_key);
    try testing.expectEqualSlices(u8, &kp.public_key, &derived);
}

test "buildNonce format" {
    const nonce = buildNonce(0x0102030405060708);
    // First 4 bytes should be zero
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0 }, nonce[0..4]);
    // Next 8 bytes should be LE counter
    try testing.expectEqualSlices(u8, &[_]u8{ 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01 }, nonce[4..12]);
}

test "INITIAL_CHAIN_KEY verification" {
    // Verify that HASH("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s") matches boringtun's constant
    var out: [32]u8 = undefined;
    Blake2s256.hash("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s", &out, .{});
    const expected = [_]u8{
        96, 226, 109, 174, 243, 39,  239, 192, 46, 195, 53,  226, 160, 37,  210, 208,
        22, 235, 66,  6,   248, 114, 119, 245, 45, 56,  209, 152, 139, 120, 205, 54,
    };
    try testing.expectEqualSlices(u8, &expected, &out);
}

test "INITIAL_CHAIN_HASH verification" {
    // Verify HASH(INITIAL_CHAIN_KEY || "WireGuard v1 zx2c4 Jason@zx2c4.com")
    const chain_key = [_]u8{
        96, 226, 109, 174, 243, 39,  239, 192, 46, 195, 53,  226, 160, 37,  210, 208,
        22, 235, 66,  6,   248, 114, 119, 245, 45, 56,  209, 152, 139, 120, 205, 54,
    };
    const result = b2sHash(&chain_key, "WireGuard v1 zx2c4 Jason@zx2c4.com");
    const expected = [_]u8{
        34, 17,  179, 97,  8,  26,  197, 102, 105, 18,  67,  219, 69,  138, 213, 50,
        45, 156, 108, 102, 34, 147, 232, 183, 14,  225, 156, 101, 186, 7,   158, 243,
    };
    try testing.expectEqualSlices(u8, &expected, &result);
}
