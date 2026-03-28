// Copyright (c) 2024 Ziguard contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
//
// WireGuard peer state management.
// Ported from boringtun (Cloudflare, Inc.; Firezone fork)

const std = @import("std");
const Tunn = @import("../noise/tunnel.zig").Tunn;
const TunnResult = @import("../noise/tunnel.zig").TunnResult;
const AllowedIps = @import("allowed_ips.zig").AllowedIps;
const IpAddr = @import("allowed_ips.zig").IpAddr;
const crypto = @import("../crypto.zig");

pub const AllowedIP = struct {
    addr: IpAddr,
    cidr: u8,
};

pub const Endpoint = struct {
    addr: ?std.net.Address = null,
    /// Connected UDP socket for fast-path send (not used in initial impl).
    conn_fd: ?std.posix.fd_t = null,
};

pub const Peer = struct {
    tunnel: Tunn,
    index: u32,
    endpoint: Endpoint,
    allowed_ips_table: AllowedIps(void),
    preshared_key: ?[32]u8,
    allocator: std.mem.Allocator,

    pub fn init(
        allocator: std.mem.Allocator,
        tunnel: Tunn,
        index: u32,
        endpoint: ?std.net.Address,
        allowed_ips: []const AllowedIP,
        preshared_key: ?[32]u8,
    ) !Peer {
        var table = AllowedIps(void).init(allocator);
        for (allowed_ips) |aip| {
            try table.insert(aip.addr, aip.cidr, {});
        }
        return .{
            .tunnel = tunnel,
            .index = index,
            .endpoint = .{ .addr = endpoint },
            .allowed_ips_table = table,
            .preshared_key = preshared_key,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Peer) void {
        self.allowed_ips_table.deinit();
        self.tunnel.deinit();
    }

    pub fn updateTimers(self: *Peer, dst: []u8, now: i128) TunnResult {
        return self.tunnel.updateTimersAt(dst, now);
    }

    pub fn setEndpoint(self: *Peer, addr: std.net.Address) void {
        self.endpoint.addr = addr;
    }

    pub fn shutdownEndpoint(self: *Peer) void {
        if (self.endpoint.conn_fd) |fd| {
            std.posix.close(fd);
            self.endpoint.conn_fd = null;
        }
    }

    pub fn isAllowedIp(self: *const Peer, addr: IpAddr) bool {
        return self.allowed_ips_table.find(addr) != null;
    }

    pub fn timeSinceLastHandshake(self: *const Peer, now: i128) ?i128 {
        return self.tunnel.timeSinceLastHandshakeAt(now);
    }

    pub fn persistentKeepalive(self: *const Peer) ?u16 {
        return self.tunnel.persistentKeepalive();
    }
};
