// Copyright (c) 2024 Ziguard contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
//
// Ported from boringtun (Cloudflare, Inc.; Firezone fork)

const std = @import("std");

/// A unique identifier for an instance of Tunn.
///
/// The top 24 bits are used as a unique, global identifier.
/// The lower 8 bits are used as a rotating session index with a given peer.
///
/// This allows for ~16M unique peers and 256 sessions per peer.
pub const Index = struct {
    value: u32 = 0,

    pub fn newLocal(idx: u32) Index {
        std.debug.assert(idx >> 24 == 0); // Must be at most a 24-bit number
        return .{ .value = idx << 8 };
    }

    pub fn fromPeer(peer: u32) Index {
        return .{ .value = peer };
    }

    pub fn wrappingIncrement(self: *Index) Index {
        const idx8: u8 = @truncate(self.value);
        self.value = (self.value & ~@as(u32, 0xff)) | @as(u32, idx8 +% 1);
        return self.*;
    }

    pub fn wrappingSub(self: Index, val: u8) Index {
        const idx8: u8 = @truncate(self.value);
        return .{ .value = (self.value & ~@as(u32, 0xff)) | @as(u32, idx8 -% val) };
    }

    pub fn toLeBytes(self: Index) [4]u8 {
        return std.mem.toBytes(std.mem.nativeToLittle(u32, self.value));
    }

    pub fn global(self: Index) usize {
        return @intCast(self.value >> 8);
    }

    pub fn session(self: Index) usize {
        return @as(usize, @as(u8, @truncate(self.value)));
    }

    pub fn eql(self: Index, other: Index) bool {
        return self.value == other.value;
    }

    pub fn eqlU32(self: Index, other: u32) bool {
        return self.value == other;
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "incrementing never changes global part" {
    var seed: [4]u8 = undefined;
    std.crypto.random.bytes(&seed);
    const raw = std.mem.readInt(u32, &seed, .little) >> 8;

    var index = Index.newLocal(raw);
    const g = index.global();

    for (0..23745) |_| {
        _ = index.wrappingIncrement();
        try testing.expectEqual(g, index.global());
    }
}

test "incrementing changes session index" {
    var seed: [4]u8 = undefined;
    std.crypto.random.bytes(&seed);
    const raw = std.mem.readInt(u32, &seed, .little) >> 8;

    var index = Index.newLocal(raw);

    // First cycle through 0..255
    for (0..256) |i| {
        try testing.expectEqual(i, index.session());
        _ = index.wrappingIncrement();
    }

    // Second cycle starts at 0 again
    for (0..256) |i| {
        try testing.expectEqual(i, index.session());
        _ = index.wrappingIncrement();
    }
}

test "toLeBytes round-trip" {
    const index = Index.newLocal(0x123);
    const bytes = index.toLeBytes();
    const recovered = std.mem.readInt(u32, &bytes, .little);
    try testing.expectEqual(index.value, recovered);
}

test "wrappingSub" {
    var index = Index.newLocal(0x1);
    // Advance session to 5
    for (0..5) |_| {
        _ = index.wrappingIncrement();
    }
    try testing.expectEqual(@as(usize, 5), index.session());

    // Sub 3 should give session 2
    const sub = index.wrappingSub(3);
    try testing.expectEqual(@as(usize, 2), sub.session());
    try testing.expectEqual(index.global(), sub.global());
}
