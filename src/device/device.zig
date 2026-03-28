// Copyright (c) 2024 Ziguard contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
//
// WireGuard device — single-threaded event loop tying together
// the TUN interface, UDP sockets, and peer management.
// Simplified port of boringtun's device/mod.rs.

const std = @import("std");
const posix = std.posix;
const crypto = @import("../crypto.zig");
const noise = @import("../noise/noise.zig");
const Tunn = noise.Tunn;
const TunnResult = @import("../noise/tunnel.zig").TunnResult;
const WireGuardError = noise.WireGuardError;
const Index = noise.Index;
const hs = @import("../noise/handshake.zig");
const AllowedIps = @import("allowed_ips.zig").AllowedIps;
const IpAddr = @import("allowed_ips.zig").IpAddr;
const Peer = @import("peer.zig").Peer;
const AllowedIP = @import("peer.zig").AllowedIP;
const TunSocket = @import("tun_darwin.zig").TunSocket;
const serialization = @import("../serialization.zig");

const MAX_UDP_SIZE: usize = 65535;

pub const DeviceConfig = struct {
    private_key: [32]u8,
    listen_port: u16 = 0,
    tun_name: []const u8 = "utun",
};

pub const PeerConfig = struct {
    public_key: [32]u8,
    preshared_key: ?[32]u8 = null,
    endpoint: ?std.net.Address = null,
    allowed_ips: []const AllowedIP = &.{},
    persistent_keepalive: ?u16 = null,
};

pub const Device = struct {
    allocator: std.mem.Allocator,
    private_key: [32]u8,
    public_key: [32]u8,
    tun: TunSocket,
    udp4: posix.fd_t,
    listen_port: u16,
    peers: std.ArrayListUnmanaged(*Peer),
    peers_by_ip: AllowedIps(*Peer),
    peers_by_idx: std.AutoHashMap(u32, *Peer),
    next_peer_index: u32,
    running: bool,
    src_buf: [MAX_UDP_SIZE]u8,
    dst_buf: [MAX_UDP_SIZE]u8,

    pub fn init(allocator: std.mem.Allocator, config: DeviceConfig) !*Device {
        const public_key = try crypto.x25519PublicKey(config.private_key);

        // Open TUN
        var tun = try TunSocket.init(config.tun_name);
        errdefer tun.deinit();
        try tun.setNonBlocking();

        // Open UDP socket
        const udp4 = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM | posix.SOCK.NONBLOCK, 0);
        errdefer posix.close(udp4);

        const bind_addr = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, config.listen_port);
        try posix.bind(udp4, &bind_addr.any, bind_addr.getOsSockLen());

        // Determine actual port if 0 was requested
        var actual_addr: posix.sockaddr = undefined;
        var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr);
        try posix.getsockname(udp4, &actual_addr, &addr_len);
        const actual_port = std.mem.bigToNative(u16, @as(*const std.posix.sockaddr.in, @ptrCast(@alignCast(&actual_addr))).port);

        const device = try allocator.create(Device);
        device.* = .{
            .allocator = allocator,
            .private_key = config.private_key,
            .public_key = public_key,
            .tun = tun,
            .udp4 = udp4,
            .listen_port = actual_port,
            .peers = .{},
            .peers_by_ip = AllowedIps(*Peer).init(allocator),
            .peers_by_idx = std.AutoHashMap(u32, *Peer).init(allocator),
            .next_peer_index = 1,
            .running = false,
            .src_buf = undefined,
            .dst_buf = undefined,
        };
        return device;
    }

    pub fn deinit(self: *Device) void {
        for (self.peers.items) |peer| {
            peer.shutdownEndpoint();
            peer.deinit();
            self.allocator.destroy(peer);
        }
        self.peers.deinit(self.allocator);
        self.peers_by_ip.deinit();
        self.peers_by_idx.deinit();
        posix.close(self.udp4);
        self.tun.deinit();
        self.allocator.destroy(self);
    }

    pub fn addPeer(self: *Device, config: PeerConfig) !void {
        const now = std.time.nanoTimestamp();
        const idx = self.next_peer_index;
        self.next_peer_index += 1;

        const tunnel = Tunn.init(
            self.allocator,
            self.private_key,
            config.public_key,
            config.preshared_key,
            config.persistent_keepalive,
            idx,
            now,
        );

        const peer = try self.allocator.create(Peer);
        peer.* = try Peer.init(
            self.allocator,
            tunnel,
            idx,
            config.endpoint,
            config.allowed_ips,
            config.preshared_key,
        );

        try self.peers.append(self.allocator, peer);
        try self.peers_by_idx.put(idx, peer);

        for (config.allowed_ips) |aip| {
            try self.peers_by_ip.insert(aip.addr, aip.cidr, peer);
        }
    }

    /// Run the main event loop using poll().
    pub fn run(self: *Device) !void {
        self.running = true;

        var name_buf: [256]u8 = undefined;
        const tun_name = try self.tun.getName(&name_buf);
        std.debug.print("Interface: {s}\n", .{tun_name});
        std.debug.print("Listening on port: {d}\n", .{self.listen_port});
        std.debug.print("Peers: {d}\n", .{self.peers.items.len});

        var last_timer_check: i128 = std.time.nanoTimestamp();
        const timer_interval: i128 = 250 * std.time.ns_per_ms;

        while (self.running) {
            var poll_fds = [_]std.posix.pollfd{
                .{ .fd = self.tun.fd(), .events = std.posix.POLL.IN, .revents = 0 },
                .{ .fd = self.udp4, .events = std.posix.POLL.IN, .revents = 0 },
            };

            // Poll with 250ms timeout for timer processing
            _ = std.posix.poll(&poll_fds, 250) catch 0;

            const now = std.time.nanoTimestamp();

            // Handle TUN packets (outbound: TUN → UDP)
            if (poll_fds[0].revents & std.posix.POLL.IN != 0) {
                self.handleTunReadable(now);
            }

            // Handle UDP packets (inbound: UDP → TUN)
            if (poll_fds[1].revents & std.posix.POLL.IN != 0) {
                self.handleUdpReadable(now);
            }

            // Timer processing
            if (now - last_timer_check >= timer_interval) {
                self.processTimers(now);
                last_timer_check = now;
            }
        }
    }

    pub fn stop(self: *Device) void {
        self.running = false;
    }

    fn handleTunReadable(self: *Device, now: i128) void {
        var iterations: usize = 100;
        while (iterations > 0) : (iterations -= 1) {
            const packet = self.tun.read(&self.src_buf) catch break;
            if (packet.len == 0) break;

            const dst_addr = Tunn.dstAddress(packet) orelse continue;
            const ip_addr: IpAddr = switch (dst_addr) {
                .v4 => |a| .{ .v4 = a },
                .v6 => |a| .{ .v6 = a },
            };

            const peer_ptr = self.peers_by_ip.find(ip_addr) orelse continue;
            const peer = peer_ptr.*;

            const result = peer.tunnel.encapsulateAt(packet, &self.dst_buf, now);
            switch (result) {
                .write_to_network => |data| {
                    self.sendToEndpoint(peer, data);
                },
                .err => {},
                .done => {},
                else => {},
            }
        }
    }

    fn handleUdpReadable(self: *Device, now: i128) void {
        var iterations: usize = 100;
        while (iterations > 0) : (iterations -= 1) {
            var src_addr: posix.sockaddr = undefined;
            var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr);

            const n = posix.recvfrom(self.udp4, &self.src_buf, 0, &src_addr, &addr_len) catch break;
            if (n == 0) break;

            const datagram = self.src_buf[0..n];
            const sender_addr = std.net.Address{ .any = @bitCast(src_addr) };

            // Find the peer for this packet
            const peer = self.findPeerForPacket(datagram) orelse continue;

            // Update endpoint
            peer.setEndpoint(sender_addr);

            // Decapsulate
            const result = peer.tunnel.decapsulateAt(null, datagram, &self.dst_buf, now);
            self.handleTunnResult(peer, result, now);

            // Flush queued packets
            while (true) {
                const flush_result = peer.tunnel.decapsulateAt(null, "", &self.dst_buf, now);
                switch (flush_result) {
                    .write_to_network => |data| self.sendToEndpoint(peer, data),
                    else => break,
                }
            }
        }
    }

    fn findPeerForPacket(self: *Device, datagram: []const u8) ?*Peer {
        const packet = Tunn.parseIncomingPacket(datagram) catch return null;
        switch (packet) {
            .handshake_init => |p| {
                // For init packets we need to check against all peers
                // by trying to parse the anonymous init
                _ = p;
                // Simplified: try each peer (O(n) but correct)
                for (self.peers.items) |peer| {
                    return peer;
                }
                return null;
            },
            .handshake_response => |p| return self.peers_by_idx.get(p.receiver_idx >> 8),
            .cookie_reply => |p| return self.peers_by_idx.get(p.receiver_idx >> 8),
            .data => |p| return self.peers_by_idx.get(p.receiver_idx >> 8),
        }
    }

    fn handleTunnResult(self: *Device, peer: *Peer, result: TunnResult, _: i128) void {
        switch (result) {
            .done => {},
            .err => {},
            .write_to_network => |data| {
                self.sendToEndpoint(peer, data);
            },
            .write_to_tunnel_v4 => |info| {
                if (peer.isAllowedIp(.{ .v4 = info.addr })) {
                    _ = self.tun.write4(info.packet);
                }
            },
            .write_to_tunnel_v6 => |info| {
                if (peer.isAllowedIp(.{ .v6 = info.addr })) {
                    _ = self.tun.write6(info.packet);
                }
            },
        }
    }

    fn sendToEndpoint(self: *Device, peer: *Peer, data: []const u8) void {
        const addr = peer.endpoint.addr orelse return;
        _ = posix.sendto(self.udp4, data, 0, &addr.any, addr.getOsSockLen()) catch {};
    }

    fn processTimers(self: *Device, now: i128) void {
        for (self.peers.items) |peer| {
            const result = peer.updateTimers(&self.dst_buf, now);
            switch (result) {
                .write_to_network => |data| {
                    self.sendToEndpoint(peer, data);
                },
                .err => |e| {
                    if (e == error.ConnectionExpired) {
                        peer.shutdownEndpoint();
                    }
                },
                else => {},
            }
        }
    }
};
