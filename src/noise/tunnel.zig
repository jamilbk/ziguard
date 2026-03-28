// Copyright (c) 2024 Ziguard contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
//
// WireGuard tunnel state machine.
// Ported from boringtun (Cloudflare, Inc.; Firezone fork)

const std = @import("std");
const crypto = @import("../crypto.zig");
const hs = @import("handshake.zig");
const Session = @import("session.zig").Session;
const PacketData = @import("session.zig").PacketData;
const data_session = @import("session.zig");
const Index = @import("index.zig").Index;
const WireGuardError = @import("errors.zig").WireGuardError;
const Timers = @import("timers.zig").Timers;
const TimerName = @import("timers.zig").TimerName;
const timer_consts = @import("timers.zig");
const RateLimiter = @import("rate_limiter.zig").RateLimiter;

const PEER_HANDSHAKE_RATE_LIMIT: u64 = 10;

const IPV4_MIN_HEADER_SIZE: usize = 20;
const IPV4_LEN_OFF: usize = 2;
const IPV4_SRC_IP_OFF: usize = 12;
const IPV4_DST_IP_OFF: usize = 16;
const IPV4_IP_SZ: usize = 4;

const IPV6_MIN_HEADER_SIZE: usize = 40;
const IPV6_LEN_OFF: usize = 4;
const IPV6_SRC_IP_OFF: usize = 8;
const IPV6_DST_IP_OFF: usize = 24;
const IPV6_IP_SZ: usize = 16;

const IP_LEN_SZ: usize = 2;

const MAX_QUEUE_DEPTH: usize = 256;
pub const N_SESSIONS: u8 = 8;

/// Describes a parsed packet from the network.
pub const Packet = union(enum) {
    handshake_init: hs.HandshakeInit,
    handshake_response: hs.HandshakeResponse,
    cookie_reply: hs.PacketCookieReply,
    data: PacketData,
};

/// Result of tunnel operations.
pub const TunnResult = union(enum) {
    done,
    err: WireGuardError,
    write_to_network: []u8,
    write_to_tunnel_v4: struct { packet: []u8, addr: [4]u8 },
    write_to_tunnel_v6: struct { packet: []u8, addr: [16]u8 },
};

/// A point-to-point WireGuard tunnel.
pub const Tunn = struct {
    handshake: hs.Handshake,
    sessions: [N_SESSIONS]?Session,
    current: Index,
    packet_queue: std.ArrayList([]u8),
    timers: Timers,
    tx_bytes: usize,
    rx_bytes: usize,
    rate_limiter: RateLimiter,
    allocator: std.mem.Allocator,

    pub fn init(
        allocator: std.mem.Allocator,
        static_private: [32]u8,
        peer_static_public: [32]u8,
        preshared_key: ?[32]u8,
        persistent_keepalive: ?u16,
        index: u32,
        now: i128,
    ) Tunn {
        const static_public = crypto.x25519PublicKey(static_private) catch [_]u8{0} ** 32;
        var rng_seed: [8]u8 = undefined;
        std.crypto.random.bytes(&rng_seed);

        return .{
            .handshake = hs.Handshake.init(
                static_private,
                static_public,
                peer_static_public,
                Index.newLocal(index),
                preshared_key,
                now,
            ),
            .sessions = [_]?Session{null} ** N_SESSIONS,
            .current = .{},
            .packet_queue = .{},
            .timers = Timers.init(persistent_keepalive, true, std.mem.readInt(u64, &rng_seed, .little), now),
            .tx_bytes = 0,
            .rx_bytes = 0,
            .rate_limiter = RateLimiter.init(static_public, PEER_HANDSHAKE_RATE_LIMIT, now),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Tunn) void {
        // Free any queued packets
        for (self.packet_queue.items) |pkt| {
            self.allocator.free(pkt);
        }
        self.packet_queue.deinit(self.allocator);
    }

    /// Parse an incoming network packet into its type.
    pub fn parseIncomingPacket(src: []const u8) WireGuardError!Packet {
        if (src.len < 4) return error.InvalidPacket;

        const packet_type = std.mem.readInt(u32, src[0..4], .little);

        return switch (packet_type) {
            hs.HANDSHAKE_INIT => blk: {
                if (src.len != hs.HANDSHAKE_INIT_SZ) break :blk error.InvalidPacket;
                break :blk .{ .handshake_init = .{
                    .sender_idx = std.mem.readInt(u32, src[4..8], .little),
                    .unencrypted_ephemeral = src[8..40],
                    .encrypted_static = src[40..88],
                    .encrypted_timestamp = src[88..116],
                } };
            },
            hs.HANDSHAKE_RESP => blk: {
                if (src.len != hs.HANDSHAKE_RESP_SZ) break :blk error.InvalidPacket;
                break :blk .{ .handshake_response = .{
                    .sender_idx = std.mem.readInt(u32, src[4..8], .little),
                    .receiver_idx = std.mem.readInt(u32, src[8..12], .little),
                    .unencrypted_ephemeral = src[12..44],
                    .encrypted_nothing = src[44..60],
                } };
            },
            hs.COOKIE_REPLY => blk: {
                if (src.len != hs.COOKIE_REPLY_SZ) break :blk error.InvalidPacket;
                break :blk .{ .cookie_reply = .{
                    .receiver_idx = std.mem.readInt(u32, src[4..8], .little),
                    .nonce = src[8..32],
                    .encrypted_cookie = src[32..64],
                } };
            },
            data_session.DATA => blk: {
                if (src.len < data_session.DATA_OVERHEAD_SZ) break :blk error.InvalidPacket;
                break :blk .{ .data = .{
                    .receiver_idx = std.mem.readInt(u32, src[4..8], .little),
                    .counter = std.mem.readInt(u64, src[8..16], .little),
                    .encrypted_encapsulated_packet = src[16..],
                } };
            },
            else => error.InvalidPacket,
        };
    }

    pub fn isExpired(self: *const Tunn) bool {
        return self.handshake.isExpired();
    }

    /// Get the destination IP address from a decapsulated packet.
    pub fn dstAddress(packet: []const u8) ?union(enum) { v4: [4]u8, v6: [16]u8 } {
        if (packet.len == 0) return null;
        return switch (packet[0] >> 4) {
            4 => if (packet.len >= IPV4_MIN_HEADER_SIZE)
                .{ .v4 = packet[IPV4_DST_IP_OFF..][0..IPV4_IP_SZ].* }
            else
                null,
            6 => if (packet.len >= IPV6_MIN_HEADER_SIZE)
                .{ .v6 = packet[IPV6_DST_IP_OFF..][0..IPV6_IP_SZ].* }
            else
                null,
            else => null,
        };
    }

    /// Encapsulate a packet from the tunnel interface.
    pub fn encapsulateAt(self: *Tunn, src: []const u8, dst: []u8, now: i128) TunnResult {
        const session_idx = self.current.session();
        if (self.sessions[session_idx]) |*session| {
            if (session.shouldUseAt(now) or !self.timers.is_initiator) {
                const packet = session.formatPacketData(src, dst) catch |e| return .{ .err = e };
                self.timerTick(.time_last_packet_sent, now);
                if (src.len > 0) {
                    self.timerTick(.time_last_data_packet_sent, now);
                }
                self.tx_bytes += src.len;
                return .{ .write_to_network = packet };
            }
        }

        // No usable session, queue and initiate handshake
        self.queuePacket(src);
        return self.formatHandshakeInitiationAt(dst, false, now);
    }

    /// Receive a UDP datagram from the network.
    pub fn decapsulateAt(self: *Tunn, src_addr: ?[]const u8, datagram: []const u8, dst: []u8, now: i128) TunnResult {
        if (datagram.len == 0) {
            return self.sendQueuedPacket(dst, now);
        }

        // For handshake packets, verify MACs via rate limiter
        const packet = parseIncomingPacket(datagram) catch |e| return .{ .err = e };

        switch (packet) {
            .handshake_init, .handshake_response => {
                const verify = self.rate_limiter.verifyPacketMacs(datagram, src_addr, now);
                switch (verify) {
                    .valid => {},
                    .invalid_mac => return .{ .err = error.InvalidMac },
                    .need_cookie_reply => |info| {
                        const cookie_reply = self.rate_limiter.formatCookieReply(info.sender_idx, info.cookie, &info.mac1, dst) catch |e| return .{ .err = e };
                        return .{ .write_to_network = cookie_reply };
                    },
                }
            },
            else => {},
        }

        return self.handleVerifiedPacket(packet, dst, now);
    }

    fn handleVerifiedPacket(self: *Tunn, packet: Packet, dst: []u8, now: i128) TunnResult {
        return switch (packet) {
            .handshake_init => |p| self.handleHandshakeInit(p, dst, now),
            .handshake_response => |p| self.handleHandshakeResponse(p, dst, now),
            .cookie_reply => |p| self.handleCookieReply(p, now),
            .data => |p| self.handleData(p, dst, now),
        };
    }

    fn handleHandshakeInit(self: *Tunn, p: hs.HandshakeInit, dst: []u8, now: i128) TunnResult {
        const result = self.handshake.receiveHandshakeInitialization(p, dst, now) catch |e| return .{ .err = e };

        const local_idx = result.session.receiving_index;
        self.sessions[local_idx.session()] = result.session;

        self.timerTick(.time_last_packet_received, now);
        self.timerTick(.time_last_packet_sent, now);
        self.timerTickSessionEstablished(false, now);

        return .{ .write_to_network = result.packet };
    }

    fn handleHandshakeResponse(self: *Tunn, p: hs.HandshakeResponse, dst: []u8, now: i128) TunnResult {
        var session = self.handshake.receiveHandshakeResponse(p, now) catch |e| return .{ .err = e };

        // Send keepalive
        const keepalive = session.formatPacketData("", dst) catch |e| return .{ .err = e };
        const local_idx = session.receiving_index;
        self.sessions[local_idx.session()] = session;

        self.timerTick(.time_last_packet_received, now);
        self.timerTickSessionEstablished(true, now);
        self.setCurrentSession(local_idx);

        return .{ .write_to_network = keepalive };
    }

    fn handleCookieReply(self: *Tunn, p: hs.PacketCookieReply, now: i128) TunnResult {
        self.handshake.receiveCookieReply(p, now) catch |e| return .{ .err = e };
        self.timerTick(.time_last_packet_received, now);
        return .done;
    }

    fn handleData(self: *Tunn, packet: PacketData, dst: []u8, now: i128) TunnResult {
        const session_idx: usize = @intCast(packet.receiver_idx % N_SESSIONS);
        const session = &(self.sessions[session_idx] orelse return .{ .err = error.NoCurrentSession });

        var session_mut = session.*;
        const decapsulated = session_mut.receivePacketData(packet, dst) catch |e| return .{ .err = e };
        self.sessions[session_idx] = session_mut;

        self.setCurrentSession(session_mut.receiving_index);
        self.timerTick(.time_last_packet_received, now);

        return self.validateDecapsulatedPacket(decapsulated, now);
    }

    fn setCurrentSession(self: *Tunn, new_idx: Index) void {
        if (self.current.eql(new_idx)) return;

        const new_session = self.sessions[new_idx.session()] orelse return;
        if (self.sessions[self.current.session()]) |current| {
            if (current.establishedAt() > new_session.establishedAt()) {
                return; // Current is newer
            }
        }
        self.current = new_idx;
    }

    /// Format a new handshake initiation message.
    pub fn formatHandshakeInitiationAt(self: *Tunn, dst: []u8, force_resend: bool, now: i128) TunnResult {
        if (self.handshake.isInProgress() and !force_resend) {
            return .done;
        }

        if (self.handshake.isExpired()) {
            self.timers.clear(now);
        }

        const starting_new = !self.handshake.isInProgress();

        const result = self.handshake.formatHandshakeInitiation(dst, now) catch |e| return .{ .err = e };
        if (starting_new) {
            self.timerTick(.time_last_handshake_started, now);
        }
        self.timerTick(.time_last_packet_sent, now);
        return .{ .write_to_network = result.packet };
    }

    /// Validate a decapsulated IP packet — check version, truncate to length, extract src IP.
    fn validateDecapsulatedPacket(self: *Tunn, packet: []u8, now: i128) TunnResult {
        if (packet.len == 0) return .done; // keepalive

        const ip_version = packet[0] >> 4;
        if (ip_version == 4 and packet.len >= IPV4_MIN_HEADER_SIZE) {
            const len = std.mem.readInt(u16, packet[IPV4_LEN_OFF..][0..2], .big);
            if (len > packet.len) return .{ .err = error.InvalidPacket };
            self.timerTick(.time_last_data_packet_received, now);
            self.rx_bytes += len;
            return .{ .write_to_tunnel_v4 = .{
                .packet = packet[0..len],
                .addr = packet[IPV4_SRC_IP_OFF..][0..4].*,
            } };
        }
        if (ip_version == 6 and packet.len >= IPV6_MIN_HEADER_SIZE) {
            const payload_len = std.mem.readInt(u16, packet[IPV6_LEN_OFF..][0..2], .big);
            const total_len = @as(usize, payload_len) + IPV6_MIN_HEADER_SIZE;
            if (total_len > packet.len) return .{ .err = error.InvalidPacket };
            self.timerTick(.time_last_data_packet_received, now);
            self.rx_bytes += total_len;
            return .{ .write_to_tunnel_v6 = .{
                .packet = packet[0..total_len],
                .addr = packet[IPV6_SRC_IP_OFF..][0..16].*,
            } };
        }

        return .{ .err = error.InvalidPacket };
    }

    fn sendQueuedPacket(self: *Tunn, dst: []u8, now: i128) TunnResult {
        if (self.dequeuePacket()) |pkt| {
            defer self.allocator.free(pkt);
            const result = self.encapsulateAt(pkt, dst, now);
            return switch (result) {
                .err => .done,
                else => result,
            };
        }
        return .done;
    }

    fn queuePacket(self: *Tunn, packet: []const u8) void {
        if (self.packet_queue.items.len >= MAX_QUEUE_DEPTH) return;
        const copy = self.allocator.dupe(u8, packet) catch return;
        self.packet_queue.append(self.allocator, copy) catch {
            self.allocator.free(copy);
        };
    }

    fn dequeuePacket(self: *Tunn) ?[]u8 {
        if (self.packet_queue.items.len == 0) return null;
        return self.packet_queue.orderedRemove(0);
    }

    // Timer helpers
    fn timerTick(self: *Tunn, timer_name: TimerName, now: i128) void {
        switch (timer_name) {
            .time_last_packet_received => {
                self.timers.want_handshake_at = null;
            },
            .time_last_packet_sent => {
                self.timers.want_passive_keepalive_at = null;
            },
            .time_last_data_packet_received => {
                self.timers.want_passive_keepalive_at = now + timer_consts.KEEPALIVE_TIMEOUT;
            },
            .time_last_data_packet_sent => {
                if (self.timers.want_handshake_at == null) {
                    self.timers.want_handshake_at = now + timer_consts.KEEPALIVE_TIMEOUT + timer_consts.REKEY_TIMEOUT;
                }
            },
            else => {},
        }
        self.timers.set(timer_name, now);
    }

    fn timerTickSessionEstablished(self: *Tunn, is_initiator: bool, now: i128) void {
        self.timerTick(.time_session_established, now);
        self.timers.is_initiator = is_initiator;
    }

    /// Update timers and potentially trigger handshakes or keepalives.
    pub fn updateTimersAt(self: *Tunn, dst: []u8, now: i128) TunnResult {
        self.timers.set(.time_last_update, now);

        if (self.timers.send_handshake_at) |scheduled| {
            if (now >= scheduled) {
                self.timers.send_handshake_at = null;
                return self.formatHandshakeInitiationAt(dst, true, now);
            }
            return .done;
        }

        var handshake_required = false;
        var keepalive_required = false;

        if (self.timers.should_reset_rr) {
            self.rate_limiter.resetCountAt(now);
        }

        // Expire old sessions
        for (&self.sessions) |*maybe_session| {
            if (maybe_session.*) |session| {
                if (session.expiredAt(now)) {
                    maybe_session.* = null;
                }
            }
        }

        // Session expired, need new handshake if we were initiator
        const current_session = self.sessions[self.current.session()];
        if (current_session == null and !self.handshake.isInProgress() and self.timers.is_initiator) {
            handshake_required = true;
        }

        const session_established = self.timers.get(.time_session_established);
        const handshake_started = self.timers.get(.time_last_handshake_started);
        _ = handshake_started;
        const data_packet_sent = self.timers.get(.time_last_data_packet_sent);
        const data_packet_received = self.timers.get(.time_last_data_packet_received);

        if (self.handshake.isExpired()) {
            return .{ .err = error.ConnectionExpired };
        }

        // Clear cookie after expiration
        if (self.handshake.cookieExpiration()) |deadline| {
            if (now >= deadline) {
                self.handshake.clearCookie();
            }
        }

        // Connection expired after REJECT_AFTER_TIME * 3
        if (now - session_established >= timer_consts.REJECT_AFTER_TIME * 3) {
            self.handshake.setExpired();
            self.clearAll(now);
            return .{ .err = error.ConnectionExpired };
        }

        if (self.handshake.timer()) |timer_info| {
            // Handshake in progress — check for retransmission
            if (now - self.timers.get(.time_last_handshake_started) >= self.timers.rekey_attempt_time) {
                self.handshake.setExpired();
                self.clearAll(now);
                return .{ .err = error.ConnectionExpired };
            }
            if (now - timer_info.time_sent >= timer_consts.REKEY_TIMEOUT) {
                handshake_required = true;
            }
        } else {
            if (self.timers.is_initiator) {
                if (session_established < data_packet_sent and now - session_established >= timer_consts.REKEY_AFTER_TIME) {
                    handshake_required = true;
                }
                if (session_established < data_packet_received and now - session_established >= timer_consts.REJECT_AFTER_TIME - timer_consts.KEEPALIVE_TIMEOUT - timer_consts.REKEY_TIMEOUT) {
                    handshake_required = true;
                }
            }

            if (self.timers.want_handshake_at) |handshake_at| {
                if (now >= handshake_at) {
                    handshake_required = true;
                }
            }

            if (!handshake_required) {
                if (self.timers.want_passive_keepalive_at) |keepalive_at| {
                    if (now >= keepalive_at) {
                        keepalive_required = true;
                    }
                }

                if (self.timers.persistent_keepalive > 0) {
                    const pk_duration = @as(i128, self.timers.persistent_keepalive) * std.time.ns_per_s;
                    if (now - self.timers.get(.time_persistent_keepalive) >= pk_duration) {
                        self.timerTick(.time_persistent_keepalive, now);
                        keepalive_required = true;
                    }
                }
            }
        }

        if (handshake_required) {
            const jitter = self.timers.getJitter();
            self.timers.send_handshake_at = now + jitter;
            return .done;
        }

        if (keepalive_required) {
            return self.encapsulateAt("", dst, now);
        }

        return .done;
    }

    fn clearAll(self: *Tunn, now: i128) void {
        for (&self.sessions) |*s| {
            s.* = null;
        }
        // Clear packet queue
        for (self.packet_queue.items) |pkt| {
            self.allocator.free(pkt);
        }
        self.packet_queue.clearRetainingCapacity();
        self.timers.clear(now);
    }

    /// Estimated time since last handshake, in nanoseconds.
    pub fn timeSinceLastHandshakeAt(self: *const Tunn, now: i128) ?i128 {
        if (self.sessions[self.current.session()] != null) {
            return now - self.timers.get(.time_session_established);
        }
        return null;
    }

    pub fn persistentKeepalive(self: *const Tunn) ?u16 {
        if (self.timers.persistent_keepalive > 0) {
            return @intCast(self.timers.persistent_keepalive);
        }
        return null;
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

fn createTwoPeers(allocator: std.mem.Allocator, now: i128) struct { my: Tunn, their: Tunn } {
    const my_kp = crypto.x25519KeyPairGenerate();
    const their_kp = crypto.x25519KeyPairGenerate();

    var seed1: [4]u8 = undefined;
    var seed2: [4]u8 = undefined;
    std.crypto.random.bytes(&seed1);
    std.crypto.random.bytes(&seed2);
    const my_idx = std.mem.readInt(u32, &seed1, .little) >> 8;
    const their_idx = std.mem.readInt(u32, &seed2, .little) >> 8;

    return .{
        .my = Tunn.init(allocator, my_kp.secret_key, their_kp.public_key, null, null, my_idx, now),
        .their = Tunn.init(allocator, their_kp.secret_key, my_kp.public_key, null, null, their_idx, now),
    };
}

test "parse incoming packet types" {
    // Handshake init (148 bytes)
    var init_buf = [_]u8{0} ** 148;
    std.mem.writeInt(u32, init_buf[0..4], hs.HANDSHAKE_INIT, .little);
    const init_pkt = try Tunn.parseIncomingPacket(&init_buf);
    try testing.expect(init_pkt == .handshake_init);

    // Handshake response (92 bytes)
    var resp_buf = [_]u8{0} ** 92;
    std.mem.writeInt(u32, resp_buf[0..4], hs.HANDSHAKE_RESP, .little);
    const resp_pkt = try Tunn.parseIncomingPacket(&resp_buf);
    try testing.expect(resp_pkt == .handshake_response);

    // Cookie reply (64 bytes)
    var cookie_buf = [_]u8{0} ** 64;
    std.mem.writeInt(u32, cookie_buf[0..4], hs.COOKIE_REPLY, .little);
    const cookie_pkt = try Tunn.parseIncomingPacket(&cookie_buf);
    try testing.expect(cookie_pkt == .cookie_reply);

    // Data packet (>= 32 bytes)
    var data_buf = [_]u8{0} ** 48;
    std.mem.writeInt(u32, data_buf[0..4], data_session.DATA, .little);
    const data_pkt = try Tunn.parseIncomingPacket(&data_buf);
    try testing.expect(data_pkt == .data);

    // Too short
    try testing.expectError(error.InvalidPacket, Tunn.parseIncomingPacket(&[_]u8{ 0, 0, 0 }));
}

test "full tunnel handshake and data" {
    const now: i128 = std.time.nanoTimestamp();
    var peers = createTwoPeers(testing.allocator, now);
    defer peers.my.deinit();
    defer peers.their.deinit();

    // Step 1: Initiator creates handshake init
    var init_dst: [2048]u8 = undefined;
    const init_result = peers.my.formatHandshakeInitiationAt(&init_dst, false, now);
    try testing.expect(init_result == .write_to_network);
    const init_packet = init_result.write_to_network;

    // Step 2: Responder decapsulates init, produces response
    var resp_dst: [2048]u8 = undefined;
    const resp_result = peers.their.decapsulateAt(null, init_packet, &resp_dst, now + 1000);
    try testing.expect(resp_result == .write_to_network);
    const resp_packet = resp_result.write_to_network;

    // Step 3: Initiator decapsulates response, produces keepalive
    var keepalive_dst: [2048]u8 = undefined;
    const keepalive_result = peers.my.decapsulateAt(null, resp_packet, &keepalive_dst, now + 2000);
    try testing.expect(keepalive_result == .write_to_network);
    const keepalive_packet = keepalive_result.write_to_network;

    // Verify keepalive is a data packet
    const parsed_keepalive = try Tunn.parseIncomingPacket(keepalive_packet);
    try testing.expect(parsed_keepalive == .data);

    // Step 4: Responder processes keepalive
    var ka_dst: [2048]u8 = undefined;
    const ka_result = peers.their.decapsulateAt(null, keepalive_packet, &ka_dst, now + 3000);
    try testing.expect(ka_result == .done); // keepalive = done

    // Step 5: Send actual data (a fake IPv4 packet)
    var ipv4_packet: [60]u8 = undefined;
    @memset(&ipv4_packet, 0);
    ipv4_packet[0] = 0x45; // IPv4, IHL=5
    std.mem.writeInt(u16, ipv4_packet[2..4], 60, .big); // Total length = 60
    @memcpy(ipv4_packet[12..16], &[4]u8{ 10, 0, 0, 1 }); // Src IP
    @memcpy(ipv4_packet[16..20], &[4]u8{ 10, 0, 0, 2 }); // Dst IP

    var data_dst: [2048]u8 = undefined;
    const send_result = peers.my.encapsulateAt(&ipv4_packet, &data_dst, now + 4000);
    try testing.expect(send_result == .write_to_network);

    var recv_dst: [2048]u8 = undefined;
    const recv_result = peers.their.decapsulateAt(null, send_result.write_to_network, &recv_dst, now + 5000);
    try testing.expect(recv_result == .write_to_tunnel_v4);
    try testing.expectEqualSlices(u8, &ipv4_packet, recv_result.write_to_tunnel_v4.packet);
}
