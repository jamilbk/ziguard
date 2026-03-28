// Copyright (c) 2024 Ziguard contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
//
// WireGuard rate limiter with cookie-based DoS prevention.
// Ported from boringtun (Cloudflare, Inc.; Firezone fork)

const std = @import("std");
const crypto = @import("../crypto.zig");
const handshake = @import("handshake.zig");
const WireGuardError = @import("errors.zig").WireGuardError;

const COOKIE_REFRESH: u64 = 128;
const COOKIE_SIZE: usize = 16;
const COOKIE_NONCE_SIZE: usize = 24;
const RESET_PERIOD: i128 = std.time.ns_per_s; // 1 second

pub const RateLimiter = struct {
    nonce_key: [32]u8,
    secret_key: [16]u8,
    start_time: i128,
    nonce_ctr: std.atomic.Value(u64),
    mac1_key: [32]u8,
    cookie_key: [32]u8,
    limit: u64,
    count: std.atomic.Value(u64),
    last_reset: i128,
    last_reset_lock: std.Thread.Mutex,

    pub fn init(public_key: [32]u8, limit: u64, now: i128) RateLimiter {
        var nonce_key: [32]u8 = undefined;
        std.crypto.random.bytes(&nonce_key);
        var secret_key: [16]u8 = undefined;
        std.crypto.random.bytes(&secret_key);

        return .{
            .nonce_key = nonce_key,
            .secret_key = secret_key,
            .start_time = now,
            .nonce_ctr = std.atomic.Value(u64).init(0),
            .mac1_key = crypto.b2sHash(handshake.LABEL_MAC1, &public_key),
            .cookie_key = crypto.b2sHash(handshake.LABEL_COOKIE, &public_key),
            .limit = limit,
            .count = std.atomic.Value(u64).init(0),
            .last_reset = now,
            .last_reset_lock = .{},
        };
    }

    /// Reset packet count (ideally called with a period of ~1 second).
    pub fn resetCountAt(self: *RateLimiter, current_time: i128) void {
        self.last_reset_lock.lock();
        defer self.last_reset_lock.unlock();
        if (current_time - self.last_reset >= RESET_PERIOD) {
            self.count.store(0, .seq_cst);
            self.last_reset = current_time;
        }
    }

    /// Compute the cookie for a given IP address at the current time.
    fn currentCookie(self: *const RateLimiter, addr_bytes: []const u8, now: i128) [COOKIE_SIZE]u8 {
        const elapsed_secs: u64 = @intCast(@divFloor(now - self.start_time, std.time.ns_per_s));
        const cur_counter = elapsed_secs / COOKIE_REFRESH;
        const counter_bytes = std.mem.toBytes(std.mem.nativeToLittle(u64, cur_counter));
        return crypto.b2sKeyedMac16_2(&self.secret_key, &counter_bytes, addr_bytes);
    }

    fn nonce(self: *RateLimiter) [COOKIE_NONCE_SIZE]u8 {
        const ctr = self.nonce_ctr.fetchAdd(1, .monotonic);
        const ctr_bytes = std.mem.toBytes(std.mem.nativeToLittle(u64, ctr));
        return crypto.b2sMac24(&self.nonce_key, &ctr_bytes);
    }

    fn isUnderLoad(self: *RateLimiter) bool {
        return self.count.fetchAdd(1, .seq_cst) >= self.limit;
    }

    /// Format a cookie reply message.
    pub fn formatCookieReply(self: *RateLimiter, idx: u32, cookie: [COOKIE_SIZE]u8, mac1: []const u8, dst: []u8) WireGuardError![]u8 {
        if (dst.len < handshake.COOKIE_REPLY_SZ) {
            return error.DestinationBufferTooSmall;
        }

        // msg.message_type = 3
        @memcpy(dst[0..4], &std.mem.toBytes(std.mem.nativeToLittle(u32, handshake.COOKIE_REPLY)));
        // msg.receiver_index
        @memcpy(dst[4..8], &std.mem.toBytes(std.mem.nativeToLittle(u32, idx)));
        // msg.nonce
        const n = self.nonce();
        @memcpy(dst[8..32], &n);
        // msg.encrypted_cookie = XAEAD(cookie_key, nonce, cookie, mac1)
        crypto.xaeadSeal(dst[32..64], self.cookie_key, n, &cookie, mac1);

        return dst[0..handshake.COOKIE_REPLY_SZ];
    }

    /// Verify the MAC fields on a handshake packet, applying rate limiting.
    /// Returns .valid, .under_load (needs cookie reply), or an error.
    pub const VerifyResult = union(enum) {
        valid,
        need_cookie_reply: struct {
            sender_idx: u32,
            cookie: [COOKIE_SIZE]u8,
            mac1: [16]u8,
        },
        invalid_mac,
    };

    pub fn verifyPacketMacs(self: *RateLimiter, src: []const u8, src_addr: ?[]const u8, now: i128) VerifyResult {
        if (src.len < 32) return .invalid_mac;

        const msg = src[0 .. src.len - 32];
        const mac1 = src[src.len - 32 ..][0..16];
        const mac2 = src[src.len - 16 ..][0..16];

        const computed_mac1 = crypto.b2sKeyedMac16(&self.mac1_key, msg);
        if (!crypto.constantTimeEq([16]u8, computed_mac1, mac1.*)) {
            return .invalid_mac;
        }

        if (self.isUnderLoad()) {
            const addr = src_addr orelse return .invalid_mac;
            const cookie = self.currentCookie(addr, now);
            // Compute mac2 over msg || mac1
            const computed_mac2 = crypto.b2sKeyedMac16_2(&cookie, msg, mac1);
            if (!crypto.constantTimeEq([16]u8, computed_mac2, mac2.*)) {
                const sender_idx = std.mem.readInt(u32, src[4..8], .little);
                return .{ .need_cookie_reply = .{
                    .sender_idx = sender_idx,
                    .cookie = cookie,
                    .mac1 = mac1.*,
                } };
            }
        }

        return .valid;
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "rate limiter basic" {
    const now: i128 = std.time.nanoTimestamp();
    var rl = RateLimiter.init([_]u8{0x42} ** 32, 100, now);

    // Should not be under load initially
    try testing.expect(!rl.isUnderLoad());

    // After limit, should be under load
    var i: u64 = 0;
    while (i < 100) : (i += 1) {
        _ = rl.isUnderLoad();
    }
    try testing.expect(rl.isUnderLoad());

    // Reset should clear count
    rl.resetCountAt(now + 2 * std.time.ns_per_s);
    try testing.expect(!rl.isUnderLoad());
}

test "cookie reply format" {
    const now: i128 = std.time.nanoTimestamp();
    var rl = RateLimiter.init([_]u8{0x42} ** 32, 100, now);

    const cookie = [_]u8{0xAA} ** 16;
    const mac1 = [_]u8{0xBB} ** 16;
    var dst: [64]u8 = undefined;
    const reply = try rl.formatCookieReply(42, cookie, &mac1, &dst);

    // Verify message type = 3
    try testing.expectEqual(@as(u32, 3), std.mem.readInt(u32, reply[0..4], .little));
    // Verify receiver index = 42
    try testing.expectEqual(@as(u32, 42), std.mem.readInt(u32, reply[4..8], .little));
    // Reply should be exactly 64 bytes
    try testing.expectEqual(@as(usize, 64), reply.len);
}
