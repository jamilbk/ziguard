// Copyright (c) 2024 Ziguard contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
//
// TAI64N timestamp implementation for WireGuard.
// Ported from boringtun (Cloudflare, Inc.; Firezone fork)

const std = @import("std");
const WireGuardError = @import("noise/errors.zig").WireGuardError;

/// A 12-byte TAI64N timestamp.
/// See https://cr.yp.to/libtai/tai64.html
pub const Tai64N = struct {
    secs: u64,
    nano: u32,

    const BASE: u64 = (1 << 62) + 37;

    pub fn zero() Tai64N {
        return .{ .secs = 0, .nano = 0 };
    }

    /// Parse a timestamp from a 12-byte buffer.
    pub fn parse(buf: *const [12]u8) Tai64N {
        const secs = std.mem.readInt(u64, buf[0..8], .big);
        const nano = std.mem.readInt(u32, buf[8..12], .big);
        return .{ .secs = secs, .nano = nano };
    }

    /// Check if this timestamp is chronologically after another.
    pub fn after(self: Tai64N, other: Tai64N) bool {
        return (self.secs > other.secs) or
            ((self.secs == other.secs) and (self.nano > other.nano));
    }

    /// Encode the timestamp into a 12-byte buffer.
    pub fn toBytes(self: Tai64N) [12]u8 {
        var buf: [12]u8 = undefined;
        std.mem.writeInt(u64, buf[0..8], self.secs, .big);
        std.mem.writeInt(u32, buf[8..12], self.nano, .big);
        return buf;
    }
};

/// Generates TAI64N timestamps relative to a monotonic clock reference.
pub const TimeStamper = struct {
    /// Unix time captured at creation
    unix_secs: u64,
    unix_nanos: u64,
    /// Monotonic time at creation (nanoseconds)
    created_at: i128,

    pub fn init(now: i128) TimeStamper {
        const epoch = std.time.epoch.EpochSeconds{
            .secs = @intCast(@divFloor(std.time.nanoTimestamp(), std.time.ns_per_s)),
        };
        _ = epoch;
        const ts = std.time.nanoTimestamp();
        const unix_secs: u64 = @intCast(@divFloor(ts, std.time.ns_per_s));
        const unix_nanos: u64 = @intCast(@mod(ts, std.time.ns_per_s));
        return .{
            .unix_secs = unix_secs,
            .unix_nanos = unix_nanos,
            .created_at = now,
        };
    }

    /// Generate a 12-byte TAI64N timestamp for the given monotonic time.
    pub fn stamp(self: TimeStamper, now: i128) [12]u8 {
        const elapsed_ns: u64 = if (now > self.created_at)
            @intCast(now - self.created_at)
        else
            0;

        const total_nanos = self.unix_nanos + elapsed_ns;
        const extra_secs = total_nanos / std.time.ns_per_s;
        const remaining_nanos = total_nanos % std.time.ns_per_s;

        const secs = self.unix_secs + extra_secs + Tai64N.BASE;
        const nano: u32 = @intCast(remaining_nanos);

        var buf: [12]u8 = undefined;
        std.mem.writeInt(u64, buf[0..8], secs, .big);
        std.mem.writeInt(u32, buf[8..12], nano, .big);
        return buf;
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "Tai64N zero" {
    const t = Tai64N.zero();
    try testing.expectEqual(@as(u64, 0), t.secs);
    try testing.expectEqual(@as(u32, 0), t.nano);
}

test "Tai64N parse and toBytes round-trip" {
    const original = Tai64N{ .secs = Tai64N.BASE + 1000, .nano = 500_000_000 };
    const bytes = original.toBytes();
    const parsed = Tai64N.parse(&bytes);
    try testing.expectEqual(original.secs, parsed.secs);
    try testing.expectEqual(original.nano, parsed.nano);
}

test "Tai64N after" {
    const t1 = Tai64N{ .secs = 100, .nano = 0 };
    const t2 = Tai64N{ .secs = 100, .nano = 1 };
    const t3 = Tai64N{ .secs = 101, .nano = 0 };

    try testing.expect(!t1.after(t1));
    try testing.expect(t2.after(t1));
    try testing.expect(!t1.after(t2));
    try testing.expect(t3.after(t1));
    try testing.expect(t3.after(t2));
}

test "TimeStamper produces monotonically increasing timestamps" {
    const now = std.time.nanoTimestamp();
    const stamper = TimeStamper.init(now);

    const stamp1 = stamper.stamp(now);
    const stamp2 = stamper.stamp(now + 1_000_000); // 1ms later

    const t1 = Tai64N.parse(&stamp1);
    const t2 = Tai64N.parse(&stamp2);
    try testing.expect(t2.after(t1));
}
