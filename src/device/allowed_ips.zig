// Copyright (c) 2024 Ziguard contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
//
// Ziguard: A WireGuard implementation in Zig.
// Ported from boringtun (Cloudflare, Inc.; Firezone fork)
//
// Longest-prefix-match IP routing table using a binary trie.

const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;

/// A tagged union representing an IPv4 or IPv6 address.
pub const IpAddr = union(enum) {
    v4: [4]u8,
    v6: [16]u8,

    /// Return the raw address bytes.
    pub fn bytes(self: IpAddr) []const u8 {
        return switch (self) {
            .v4 => |*v| v,
            .v6 => |*v| v,
        };
    }

    /// Return the maximum prefix length for this address family.
    pub fn maxCidr(self: IpAddr) u8 {
        return switch (self) {
            .v4 => 32,
            .v6 => 128,
        };
    }
};

/// A longest-prefix-match IP routing table backed by a binary trie.
///
/// `T` is the type of data associated with each CIDR entry.
pub fn AllowedIps(comptime T: type) type {
    return struct {
        const Self = @This();

        const Node = struct {
            children: [2]?*Node,
            data: ?T,
        };

        allocator: Allocator,
        root_v4: ?*Node,
        root_v6: ?*Node,

        /// Create a new, empty AllowedIps table.
        pub fn init(allocator: Allocator) Self {
            return .{
                .allocator = allocator,
                .root_v4 = null,
                .root_v6 = null,
            };
        }

        /// Free all trie nodes.
        pub fn deinit(self: *Self) void {
            freeSubtree(self.allocator, self.root_v4);
            freeSubtree(self.allocator, self.root_v6);
            self.root_v4 = null;
            self.root_v6 = null;
        }

        /// Insert a CIDR entry into the table.
        ///
        /// `addr` is the network address, `cidr` is the prefix length,
        /// and `data` is the value to associate with the prefix.
        pub fn insert(self: *Self, addr: IpAddr, cidr: u8, data: T) !void {
            const root_ptr: *?*Node = switch (addr) {
                .v4 => &self.root_v4,
                .v6 => &self.root_v6,
            };
            const addr_bytes = addr.bytes();
            const max_cidr = addr.maxCidr();
            const prefix_len: u8 = @min(cidr, max_cidr);

            var current: *?*Node = root_ptr;

            var i: u8 = 0;
            while (i < prefix_len) : (i += 1) {
                const node = try ensureNode(self.allocator, current);
                const byte_idx = i / 8;
                const bit_idx: u3 = @intCast(7 - (i % 8));
                const bit: u1 = @intCast((addr_bytes[byte_idx] >> bit_idx) & 1);
                current = &node.children[bit];
            }

            const node = try ensureNode(self.allocator, current);
            node.data = data;
        }

        /// Find the longest-prefix match for the given address.
        ///
        /// Returns a pointer to the data associated with the most-specific
        /// matching prefix, or null if no prefix matches.
        pub fn find(self: *const Self, addr: IpAddr) ?*const T {
            var current_opt: ?*const Node = switch (addr) {
                .v4 => self.root_v4,
                .v6 => self.root_v6,
            };
            const addr_bytes = addr.bytes();
            const max_bits = addr.maxCidr();

            var best: ?*const T = null;

            var i: u8 = 0;
            while (i < max_bits) : (i += 1) {
                const current = current_opt orelse break;

                if (current.data != null) {
                    best = &current.data.?;
                }

                const byte_idx = i / 8;
                const bit_idx: u3 = @intCast(7 - (i % 8));
                const bit: u1 = @intCast((addr_bytes[byte_idx] >> bit_idx) & 1);
                current_opt = current.children[bit];
            }

            // Check the final node at max depth.
            if (current_opt) |current| {
                if (current.data != null) {
                    best = &current.data.?;
                }
            }

            return best;
        }

        /// Remove all entries whose data matches the given predicate.
        ///
        /// Nodes are not freed; only their data is cleared.
        pub fn remove(self: *Self, predicate: *const fn (*const T) bool) void {
            removeFromSubtree(self.root_v4, predicate);
            removeFromSubtree(self.root_v6, predicate);
        }

        /// Remove all entries from the table and free all nodes.
        pub fn clear(self: *Self) void {
            self.deinit();
        }

        // ----- internal helpers -----

        fn ensureNode(allocator: Allocator, slot: *?*Node) !*Node {
            if (slot.*) |node| return node;
            const node = try allocator.create(Node);
            node.* = .{
                .children = .{ null, null },
                .data = null,
            };
            slot.* = node;
            return node;
        }

        fn freeSubtree(allocator: Allocator, root: ?*Node) void {
            const node = root orelse return;
            freeSubtree(allocator, node.children[0]);
            freeSubtree(allocator, node.children[1]);
            allocator.destroy(node);
        }

        fn removeFromSubtree(root: ?*Node, predicate: *const fn (*const T) bool) void {
            const node = root orelse return;
            if (node.data) |*d| {
                if (predicate(d)) {
                    node.data = null;
                }
            }
            removeFromSubtree(node.children[0], predicate);
            removeFromSubtree(node.children[1], predicate);
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "insert and find IPv4 entries" {
    var table = AllowedIps(u32).init(testing.allocator);
    defer table.deinit();

    // 10.0.0.0/8 -> 1
    try table.insert(.{ .v4 = .{ 10, 0, 0, 0 } }, 8, 1);
    // 192.168.1.0/24 -> 2
    try table.insert(.{ .v4 = .{ 192, 168, 1, 0 } }, 24, 2);

    const r1 = table.find(.{ .v4 = .{ 10, 1, 2, 3 } });
    try testing.expect(r1 != null);
    try testing.expectEqual(@as(u32, 1), r1.?.*);

    const r2 = table.find(.{ .v4 = .{ 192, 168, 1, 50 } });
    try testing.expect(r2 != null);
    try testing.expectEqual(@as(u32, 2), r2.?.*);
}

test "longest-prefix match: more specific wins" {
    var table = AllowedIps(u32).init(testing.allocator);
    defer table.deinit();

    // 10.0.0.0/8  -> 1 (less specific)
    try table.insert(.{ .v4 = .{ 10, 0, 0, 0 } }, 8, 1);
    // 10.0.1.0/24 -> 2 (more specific)
    try table.insert(.{ .v4 = .{ 10, 0, 1, 0 } }, 24, 2);

    // Address in /24 should match the more specific entry.
    const r1 = table.find(.{ .v4 = .{ 10, 0, 1, 5 } });
    try testing.expect(r1 != null);
    try testing.expectEqual(@as(u32, 2), r1.?.*);

    // Address outside /24 but inside /8 should match the broader entry.
    const r2 = table.find(.{ .v4 = .{ 10, 0, 2, 5 } });
    try testing.expect(r2 != null);
    try testing.expectEqual(@as(u32, 1), r2.?.*);
}

test "insert and find IPv6 entries" {
    var table = AllowedIps(u32).init(testing.allocator);
    defer table.deinit();

    // fd00::/8 -> 10
    var addr1 = [_]u8{0} ** 16;
    addr1[0] = 0xfd;
    try table.insert(.{ .v6 = addr1 }, 8, 10);

    var lookup = [_]u8{0} ** 16;
    lookup[0] = 0xfd;
    lookup[1] = 0xab;
    lookup[15] = 0x01;

    const r = table.find(.{ .v6 = lookup });
    try testing.expect(r != null);
    try testing.expectEqual(@as(u32, 10), r.?.*);
}

test "clear removes all entries" {
    var table = AllowedIps(u32).init(testing.allocator);
    // No defer deinit needed since clear frees everything, but we still
    // call deinit in case of test failure before clear is reached.
    defer table.deinit();

    try table.insert(.{ .v4 = .{ 10, 0, 0, 0 } }, 8, 1);
    try table.insert(.{ .v4 = .{ 192, 168, 0, 0 } }, 16, 2);

    table.clear();

    try testing.expect(table.find(.{ .v4 = .{ 10, 0, 0, 1 } }) == null);
    try testing.expect(table.find(.{ .v4 = .{ 192, 168, 1, 1 } }) == null);
}

test "find returns null for no match" {
    var table = AllowedIps(u32).init(testing.allocator);
    defer table.deinit();

    // Table is empty.
    try testing.expect(table.find(.{ .v4 = .{ 10, 0, 0, 1 } }) == null);

    // Insert one prefix and look up a non-matching address.
    try table.insert(.{ .v4 = .{ 192, 168, 1, 0 } }, 24, 1);
    try testing.expect(table.find(.{ .v4 = .{ 10, 0, 0, 1 } }) == null);
}

test "remove entries matching predicate" {
    var table = AllowedIps(u32).init(testing.allocator);
    defer table.deinit();

    try table.insert(.{ .v4 = .{ 10, 0, 0, 0 } }, 8, 1);
    try table.insert(.{ .v4 = .{ 192, 168, 0, 0 } }, 16, 2);

    // Remove entries with data == 1.
    const S = struct {
        fn pred(val: *const u32) bool {
            return val.* == 1;
        }
    };
    table.remove(&S.pred);

    try testing.expect(table.find(.{ .v4 = .{ 10, 0, 0, 1 } }) == null);

    const r = table.find(.{ .v4 = .{ 192, 168, 1, 1 } });
    try testing.expect(r != null);
    try testing.expectEqual(@as(u32, 2), r.?.*);
}
