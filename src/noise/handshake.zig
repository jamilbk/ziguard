// Copyright (c) 2024 Ziguard contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
//
// WireGuard Noise IKpsk2 handshake protocol.
// Ported from boringtun (Cloudflare, Inc.; Firezone fork)

const std = @import("std");
const crypto = @import("../crypto.zig");
const Tai64N = @import("../tai64n.zig").Tai64N;
const TimeStamper = @import("../tai64n.zig").TimeStamper;
const Index = @import("index.zig").Index;
const Session = @import("session.zig").Session;
const WireGuardError = @import("errors.zig").WireGuardError;

const KEY_LEN: usize = 32;
const TIMESTAMP_LEN: usize = 12;

// Packet type constants
pub const HANDSHAKE_INIT: u32 = 1;
pub const HANDSHAKE_RESP: u32 = 2;
pub const COOKIE_REPLY: u32 = 3;

// Packet size constants
pub const HANDSHAKE_INIT_SZ: usize = 148;
pub const HANDSHAKE_RESP_SZ: usize = 92;
pub const COOKIE_REPLY_SZ: usize = 64;

pub const LABEL_MAC1: *const [8]u8 = "mac1----";
pub const LABEL_COOKIE: *const [8]u8 = "cookie--";

pub const COOKIE_EXPIRATION_TIME: i128 = 120 * std.time.ns_per_s;

// Noise protocol construction and identifier strings
const CONSTRUCTION: []const u8 = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: []const u8 = "WireGuard v1 zx2c4 Jason@zx2c4.com";

// Pre-computed initial chain key: HASH(CONSTRUCTION)
const INITIAL_CHAIN_KEY: [KEY_LEN]u8 = blk: {
    @setEvalBranchQuota(10000);
    var out: [32]u8 = undefined;
    crypto.Blake2s256.hash(CONSTRUCTION, &out, .{});
    break :blk out;
};

// Pre-computed initial chain hash: HASH(INITIAL_CHAIN_KEY || IDENTIFIER)
const INITIAL_CHAIN_HASH: [KEY_LEN]u8 = blk: {
    @setEvalBranchQuota(10000);
    break :blk crypto.b2sHash(&INITIAL_CHAIN_KEY, IDENTIFIER);
};

/// Parsed handshake init packet fields (references into the raw packet).
pub const HandshakeInit = struct {
    sender_idx: u32,
    unencrypted_ephemeral: *const [32]u8,
    encrypted_static: []const u8, // 32 + 16 = 48 bytes
    encrypted_timestamp: []const u8, // 12 + 16 = 28 bytes
};

/// Parsed handshake response packet fields.
pub const HandshakeResponse = struct {
    sender_idx: u32,
    receiver_idx: u32,
    unencrypted_ephemeral: *const [32]u8,
    encrypted_nothing: []const u8, // 0 + 16 = 16 bytes
};

/// Parsed cookie reply packet fields.
pub const PacketCookieReply = struct {
    receiver_idx: u32,
    nonce: *const [24]u8,
    encrypted_cookie: []const u8, // 16 + 16 = 32 bytes
};

/// Result of parsing an anonymous handshake init (without knowing the peer).
pub const HalfHandshake = struct {
    peer_index: u32,
    peer_static_public: [32]u8,
};

/// Parameters used by the noise protocol.
const NoiseParams = struct {
    static_public: [32]u8,
    static_private: [32]u8,
    peer_static_public: [32]u8,
    static_shared: [32]u8,
    sending_mac1_key: [32]u8,
    preshared_key: [32]u8,

    fn init(
        static_private: [32]u8,
        static_public: [32]u8,
        peer_static_public: [32]u8,
        preshared_key: ?[32]u8,
    ) NoiseParams {
        const static_shared = crypto.x25519(static_private, peer_static_public) catch [_]u8{0} ** 32;
        const sending_mac1_key = crypto.b2sHash(LABEL_MAC1, &peer_static_public);
        return .{
            .static_public = static_public,
            .static_private = static_private,
            .peer_static_public = peer_static_public,
            .static_shared = static_shared,
            .sending_mac1_key = sending_mac1_key,
            .preshared_key = preshared_key orelse [_]u8{0} ** 32,
        };
    }

    fn setStaticPrivate(self: *NoiseParams, static_private: [32]u8, static_public: [32]u8) void {
        self.static_private = static_private;
        self.static_public = static_public;
        self.static_shared = crypto.x25519(self.static_private, self.peer_static_public) catch [_]u8{0} ** 32;
    }
};

/// State preserved from a sent handshake init, awaiting response.
const HandshakeInitSentState = struct {
    local_index: Index,
    hash: [KEY_LEN]u8,
    chaining_key: [KEY_LEN]u8,
    ephemeral_private: [32]u8,
    time_sent: i128,
};

const HandshakeState = union(enum) {
    none,
    init_sent: HandshakeInitSentState,
    expired,
};

const WriteCookie = struct {
    value: [16]u8,
    received_at: i128,
};

const Cookies = struct {
    last_mac1: ?[16]u8 = null,
    index: Index = .{},
    write_cookie: ?WriteCookie = null,
};

/// Result of handshake operations that produce a packet and session.
pub const HandshakeResult = struct {
    packet: []u8,
    session: Session,
};

/// Result of handshake initiation (packet + index).
pub const HandshakeInitResult = struct {
    packet: []u8,
    index: Index,
};

/// The WireGuard Noise handshake state machine.
pub const Handshake = struct {
    params: NoiseParams,
    next_index: Index,
    previous: HandshakeState,
    state: HandshakeState,
    cookies: Cookies,
    last_handshake_timestamp: Tai64N,
    stamper: TimeStamper,
    last_rtt: ?u32,

    pub fn init(
        static_private: [32]u8,
        static_public: [32]u8,
        peer_static_public: [32]u8,
        global_idx: Index,
        preshared_key: ?[32]u8,
        now: i128,
    ) Handshake {
        return .{
            .params = NoiseParams.init(static_private, static_public, peer_static_public, preshared_key),
            .next_index = global_idx,
            .previous = .none,
            .state = .none,
            .last_handshake_timestamp = Tai64N.zero(),
            .stamper = TimeStamper.init(now),
            .cookies = .{},
            .last_rtt = null,
        };
    }

    pub fn remoteStaticPublic(self: *const Handshake) [32]u8 {
        return self.params.peer_static_public;
    }

    pub fn presharedKey(self: *const Handshake) [32]u8 {
        return self.params.preshared_key;
    }

    pub fn isInProgress(self: *const Handshake) bool {
        return switch (self.state) {
            .init_sent => true,
            else => false,
        };
    }

    pub fn timer(self: *const Handshake) ?struct { time_sent: i128, local_index: Index } {
        return switch (self.state) {
            .init_sent => |s| .{ .time_sent = s.time_sent, .local_index = s.local_index },
            else => null,
        };
    }

    pub fn setExpired(self: *Handshake) void {
        self.previous = .expired;
        self.state = .expired;
    }

    pub fn isExpired(self: *const Handshake) bool {
        return switch (self.state) {
            .expired => true,
            else => false,
        };
    }

    pub fn cookieExpiration(self: *const Handshake) ?i128 {
        const wc = self.cookies.write_cookie orelse return null;
        return wc.received_at + COOKIE_EXPIRATION_TIME;
    }

    pub fn clearCookie(self: *Handshake) void {
        self.cookies.write_cookie = null;
    }

    pub fn setStaticPrivate(self: *Handshake, private_key: [32]u8, public_key: [32]u8) void {
        self.params.setStaticPrivate(private_key, public_key);
    }

    /// Create and format a handshake initiation message.
    /// Returns the formatted packet slice and the local session index.
    pub fn formatHandshakeInitiation(self: *Handshake, dst: []u8, now: i128) WireGuardError!HandshakeInitResult {
        if (dst.len < HANDSHAKE_INIT_SZ) {
            return error.DestinationBufferTooSmall;
        }

        var local_index = self.next_index.wrappingIncrement();
        _ = &local_index;
        self.next_index = local_index;

        // initiator.chaining_key = HASH(CONSTRUCTION)
        var chaining_key = INITIAL_CHAIN_KEY;
        // initiator.hash = HASH(HASH(INITIAL_CHAIN_KEY || IDENTIFIER) || responder.static_public)
        var hash = crypto.b2sHash(&INITIAL_CHAIN_HASH, &self.params.peer_static_public);
        // initiator.ephemeral_private = DH_GENERATE()
        const ephemeral = crypto.x25519KeyPairGenerate();

        // msg.message_type = 1, msg.reserved_zero = {0, 0, 0}
        @memcpy(dst[0..4], &std.mem.toBytes(std.mem.nativeToLittle(u32, HANDSHAKE_INIT)));
        // msg.sender_index = little_endian(initiator.sender_index)
        @memcpy(dst[4..8], &local_index.toLeBytes());
        // msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
        @memcpy(dst[8..40], &ephemeral.public_key);

        // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
        hash = crypto.b2sHash(&hash, &ephemeral.public_key);
        // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = crypto.b2sHmac(&crypto.b2sHmac(&chaining_key, &ephemeral.public_key), &[_]u8{0x01});
        // temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
        const ephemeral_shared = crypto.x25519(ephemeral.secret_key, self.params.peer_static_public) catch return error.WrongKey;
        var temp = crypto.b2sHmac(&chaining_key, &ephemeral_shared);
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = crypto.b2sHmac(&temp, &[_]u8{0x01});
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        var key = crypto.b2sHmac2(&temp, &chaining_key, &[_]u8{0x02});
        // msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
        crypto.aeadChaCha20Seal(dst[40..88], key, 0, &self.params.static_public, &hash);
        // initiator.hash = HASH(initiator.hash || msg.encrypted_static)
        hash = crypto.b2sHash(&hash, dst[40..88]);
        // temp = HMAC(initiator.chaining_key, DH(initiator.static_private, responder.static_public))
        temp = crypto.b2sHmac(&chaining_key, &self.params.static_shared);
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = crypto.b2sHmac(&temp, &[_]u8{0x01});
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        key = crypto.b2sHmac2(&temp, &chaining_key, &[_]u8{0x02});
        // msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
        const timestamp = self.stamper.stamp(now);
        crypto.aeadChaCha20Seal(dst[88..116], key, 0, &timestamp, &hash);
        // initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp)
        hash = crypto.b2sHash(&hash, dst[88..116]);

        // Save state
        self.previous = self.state;
        self.state = .{
            .init_sent = .{
                .local_index = local_index,
                .chaining_key = chaining_key,
                .hash = hash,
                .ephemeral_private = ephemeral.secret_key,
                .time_sent = now,
            },
        };

        // Append MAC1 and MAC2
        const packet = try self.appendMac1AndMac2(local_index, dst[0..HANDSHAKE_INIT_SZ]);
        return .{ .packet = packet, .index = local_index };
    }

    /// Process a received handshake initiation and produce a response.
    pub fn receiveHandshakeInitialization(self: *Handshake, packet: HandshakeInit, dst: []u8, now: i128) WireGuardError!HandshakeResult {
        // initiator.chaining_key = HASH(CONSTRUCTION)
        var chaining_key = INITIAL_CHAIN_KEY;
        // initiator.hash = HASH(HASH(INITIAL_CHAIN_KEY || IDENTIFIER) || responder.static_public)
        var hash = crypto.b2sHash(&INITIAL_CHAIN_HASH, &self.params.static_public);
        // msg.sender_index
        const peer_index = packet.sender_idx;
        // msg.unencrypted_ephemeral
        const peer_ephemeral_public = packet.unencrypted_ephemeral.*;
        // initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)
        hash = crypto.b2sHash(&hash, &peer_ephemeral_public);
        // temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = crypto.b2sHmac(&crypto.b2sHmac(&chaining_key, &peer_ephemeral_public), &[_]u8{0x01});
        // temp = HMAC(initiator.chaining_key, DH(responder.static_private, initiator.ephemeral_public))
        const ephemeral_shared = crypto.x25519(self.params.static_private, peer_ephemeral_public) catch return error.WrongKey;
        var temp = crypto.b2sHmac(&chaining_key, &ephemeral_shared);
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = crypto.b2sHmac(&temp, &[_]u8{0x01});
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        var key = crypto.b2sHmac2(&temp, &chaining_key, &[_]u8{0x02});

        // msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
        var peer_static_public_decrypted: [KEY_LEN]u8 = undefined;
        crypto.aeadChaCha20Open(&peer_static_public_decrypted, key, 0, packet.encrypted_static, &hash) catch return error.InvalidAeadTag;

        if (!crypto.constantTimeEq([32]u8, self.params.peer_static_public, peer_static_public_decrypted)) {
            return error.WrongKey;
        }

        // initiator.hash = HASH(initiator.hash || msg.encrypted_static)
        hash = crypto.b2sHash(&hash, packet.encrypted_static);
        // temp = HMAC(initiator.chaining_key, DH(initiator.static_private, responder.static_public))
        temp = crypto.b2sHmac(&chaining_key, &self.params.static_shared);
        // initiator.chaining_key = HMAC(temp, 0x1)
        chaining_key = crypto.b2sHmac(&temp, &[_]u8{0x01});
        // key = HMAC(temp, initiator.chaining_key || 0x2)
        key = crypto.b2sHmac2(&temp, &chaining_key, &[_]u8{0x02});

        // msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
        var timestamp_buf: [TIMESTAMP_LEN]u8 = undefined;
        crypto.aeadChaCha20Open(&timestamp_buf, key, 0, packet.encrypted_timestamp, &hash) catch return error.InvalidAeadTag;

        const timestamp = Tai64N.parse(&timestamp_buf);
        if (!timestamp.after(self.last_handshake_timestamp)) {
            return error.WrongTai64nTimestamp;
        }
        self.last_handshake_timestamp = timestamp;

        // initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp)
        hash = crypto.b2sHash(&hash, packet.encrypted_timestamp);

        return self.formatHandshakeResponse(hash, chaining_key, peer_ephemeral_public, peer_index, dst, now);
    }

    /// Process a received handshake response and establish a session.
    pub fn receiveHandshakeResponse(self: *Handshake, packet: HandshakeResponse, now: i128) WireGuardError!Session {
        // Check if there is a handshake awaiting a response
        const LookupResult = struct { state: HandshakeInitSentState, is_previous: bool };
        const state_result: LookupResult = blk: {
            switch (self.state) {
                .init_sent => |s| {
                    if (s.local_index.eqlU32(packet.receiver_idx)) {
                        break :blk .{ .state = s, .is_previous = false };
                    }
                },
                else => {},
            }
            switch (self.previous) {
                .init_sent => |s| {
                    if (s.local_index.eqlU32(packet.receiver_idx)) {
                        break :blk .{ .state = s, .is_previous = true };
                    }
                },
                else => {},
            }
            return error.UnexpectedPacket;
        };

        const state = state_result.state;
        const is_previous = state_result.is_previous;
        const peer_index = packet.sender_idx;
        const local_index = state.local_index;

        const unencrypted_ephemeral = packet.unencrypted_ephemeral.*;
        // responder.hash = HASH(responder.hash || msg.unencrypted_ephemeral)
        var hash = crypto.b2sHash(&state.hash, &unencrypted_ephemeral);
        // temp = HMAC(responder.chaining_key, msg.unencrypted_ephemeral)
        var temp = crypto.b2sHmac(&state.chaining_key, &unencrypted_ephemeral);
        // responder.chaining_key = HMAC(temp, 0x1)
        var chaining_key = crypto.b2sHmac(&temp, &[_]u8{0x01});
        // temp = HMAC(responder.chaining_key, DH(initiator.ephemeral_private, responder.ephemeral_public))
        const ephemeral_shared = crypto.x25519(state.ephemeral_private, unencrypted_ephemeral) catch return error.WrongKey;
        temp = crypto.b2sHmac(&chaining_key, &ephemeral_shared);
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = crypto.b2sHmac(&temp, &[_]u8{0x01});
        // temp = HMAC(responder.chaining_key, DH(initiator.static_private, responder.ephemeral_public))
        const static_ephemeral = crypto.x25519(self.params.static_private, unencrypted_ephemeral) catch return error.WrongKey;
        temp = crypto.b2sHmac(&chaining_key, &static_ephemeral);
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = crypto.b2sHmac(&temp, &[_]u8{0x01});
        // temp = HMAC(responder.chaining_key, preshared_key)
        temp = crypto.b2sHmac(&chaining_key, &self.params.preshared_key);
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = crypto.b2sHmac(&temp, &[_]u8{0x01});
        // temp2 = HMAC(temp, responder.chaining_key || 0x2)
        const temp2 = crypto.b2sHmac2(&temp, &chaining_key, &[_]u8{0x02});
        // key = HMAC(temp, temp2 || 0x3)
        const key = crypto.b2sHmac2(&temp, &temp2, &[_]u8{0x03});
        // responder.hash = HASH(responder.hash || temp2)
        hash = crypto.b2sHash(&hash, &temp2);

        // msg.encrypted_nothing = AEAD(key, 0, [empty], responder.hash)
        var empty: [0]u8 = .{};
        crypto.aeadChaCha20Open(&empty, key, 0, packet.encrypted_nothing, &hash) catch return error.InvalidAeadTag;

        // Derive session keys
        const temp1_final = crypto.b2sHmac(&chaining_key, "");
        const sending_key = crypto.b2sHmac(&temp1_final, &[_]u8{0x01});
        const receiving_key = crypto.b2sHmac2(&temp1_final, &sending_key, &[_]u8{0x02});

        const rtt_ns = now - state.time_sent;
        self.last_rtt = @intCast(@divFloor(rtt_ns, std.time.ns_per_ms));

        if (is_previous) {
            self.previous = .none;
        } else {
            self.state = .none;
        }

        return Session.init(local_index, Index.fromPeer(peer_index), receiving_key, sending_key, now);
    }

    /// Process a received cookie reply.
    pub fn receiveCookieReply(self: *Handshake, packet: PacketCookieReply, now: i128) WireGuardError!void {
        const mac1 = self.cookies.last_mac1 orelse return error.UnexpectedPacket;
        const local_index = self.cookies.index;
        if (!local_index.eqlU32(packet.receiver_idx)) {
            return error.WrongIndex;
        }

        // msg.encrypted_cookie = XAEAD(HASH(LABEL_COOKIE || responder.static_public), msg.nonce, cookie, last_received_msg.mac1)
        const key = crypto.b2sHash(LABEL_COOKIE, &self.params.peer_static_public);
        var cookie: [16]u8 = undefined;
        crypto.xaeadOpen(&cookie, key, packet.nonce.*, packet.encrypted_cookie, &mac1) catch return error.InvalidAeadTag;

        self.cookies.write_cookie = .{
            .value = cookie,
            .received_at = now,
        };
    }

    /// Compute and append MAC1 and MAC2 to a handshake message.
    fn appendMac1AndMac2(self: *Handshake, local_index: Index, dst: []u8) WireGuardError![]u8 {
        const mac1_off = dst.len - 32;
        const mac2_off = dst.len - 16;

        // msg.mac1 = MAC(HASH(LABEL_MAC1 || responder.static_public), msg[0:offsetof(msg.mac1)])
        const msg_mac1 = crypto.b2sKeyedMac16(&self.params.sending_mac1_key, dst[0..mac1_off]);
        @memcpy(dst[mac1_off..mac2_off], &msg_mac1);

        // msg.mac2 = MAC(initiator.last_received_cookie, msg[0:offsetof(msg.mac2)])
        if (self.cookies.write_cookie) |wc| {
            const msg_mac2 = crypto.b2sKeyedMac16(&wc.value, dst[0..mac2_off]);
            @memcpy(dst[mac2_off..], &msg_mac2);
        } else {
            @memset(dst[mac2_off..], 0);
        }

        self.cookies.index = local_index;
        self.cookies.last_mac1 = msg_mac1;
        return dst;
    }

    /// Format a handshake response (called after receiving a valid init).
    fn formatHandshakeResponse(
        self: *Handshake,
        hash_in: [KEY_LEN]u8,
        chaining_key_in: [KEY_LEN]u8,
        peer_ephemeral_public: [32]u8,
        peer_index: u32,
        dst: []u8,
        now: i128,
    ) WireGuardError!HandshakeResult {
        if (dst.len < HANDSHAKE_RESP_SZ) {
            return error.DestinationBufferTooSmall;
        }

        var hash = hash_in;
        var chaining_key = chaining_key_in;

        // responder.ephemeral_private = DH_GENERATE()
        const ephemeral = crypto.x25519KeyPairGenerate();
        var local_index = self.next_index.wrappingIncrement();
        _ = &local_index;
        self.next_index = local_index;

        // msg.message_type = 2
        @memcpy(dst[0..4], &std.mem.toBytes(std.mem.nativeToLittle(u32, HANDSHAKE_RESP)));
        // msg.sender_index
        @memcpy(dst[4..8], &local_index.toLeBytes());
        // msg.receiver_index
        @memcpy(dst[8..12], &std.mem.toBytes(std.mem.nativeToLittle(u32, peer_index)));
        // msg.unencrypted_ephemeral
        @memcpy(dst[12..44], &ephemeral.public_key);

        // responder.hash = HASH(responder.hash || msg.unencrypted_ephemeral)
        hash = crypto.b2sHash(&hash, &ephemeral.public_key);
        // temp = HMAC(responder.chaining_key, msg.unencrypted_ephemeral)
        var temp = crypto.b2sHmac(&chaining_key, &ephemeral.public_key);
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = crypto.b2sHmac(&temp, &[_]u8{0x01});
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.ephemeral_public))
        const ephemeral_shared = crypto.x25519(ephemeral.secret_key, peer_ephemeral_public) catch return error.WrongKey;
        temp = crypto.b2sHmac(&chaining_key, &ephemeral_shared);
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = crypto.b2sHmac(&temp, &[_]u8{0x01});
        // temp = HMAC(responder.chaining_key, DH(responder.ephemeral_private, initiator.static_public))
        const static_ephemeral = crypto.x25519(ephemeral.secret_key, self.params.peer_static_public) catch return error.WrongKey;
        temp = crypto.b2sHmac(&chaining_key, &static_ephemeral);
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = crypto.b2sHmac(&temp, &[_]u8{0x01});
        // temp = HMAC(responder.chaining_key, preshared_key)
        temp = crypto.b2sHmac(&chaining_key, &self.params.preshared_key);
        // responder.chaining_key = HMAC(temp, 0x1)
        chaining_key = crypto.b2sHmac(&temp, &[_]u8{0x01});
        // temp2 = HMAC(temp, responder.chaining_key || 0x2)
        const temp2 = crypto.b2sHmac2(&temp, &chaining_key, &[_]u8{0x02});
        // key = HMAC(temp, temp2 || 0x3)
        const key = crypto.b2sHmac2(&temp, &temp2, &[_]u8{0x03});
        // responder.hash = HASH(responder.hash || temp2)
        hash = crypto.b2sHash(&hash, &temp2);
        // msg.encrypted_nothing = AEAD(key, 0, [empty], responder.hash)
        crypto.aeadChaCha20Seal(dst[44..60], key, 0, "", &hash);

        // Derive session keys
        const temp1_final = crypto.b2sHmac(&chaining_key, "");
        const receiving_key = crypto.b2sHmac(&temp1_final, &[_]u8{0x01});
        const sending_key = crypto.b2sHmac2(&temp1_final, &receiving_key, &[_]u8{0x02});

        const packet = try self.appendMac1AndMac2(local_index, dst[0..HANDSHAKE_RESP_SZ]);

        return .{
            .packet = packet,
            .session = Session.init(local_index, Index.fromPeer(peer_index), receiving_key, sending_key, now),
        };
    }
};

/// Parse a handshake init without knowing the peer (anonymous parse).
pub fn parseHandshakeAnon(
    static_private: [32]u8,
    static_public: [32]u8,
    packet: HandshakeInit,
) WireGuardError!HalfHandshake {
    const peer_index = packet.sender_idx;
    var chaining_key = INITIAL_CHAIN_KEY;
    var hash = crypto.b2sHash(&INITIAL_CHAIN_HASH, &static_public);
    const peer_ephemeral_public = packet.unencrypted_ephemeral.*;

    hash = crypto.b2sHash(&hash, &peer_ephemeral_public);
    chaining_key = crypto.b2sHmac(&crypto.b2sHmac(&chaining_key, &peer_ephemeral_public), &[_]u8{0x01});

    const ephemeral_shared = crypto.x25519(static_private, peer_ephemeral_public) catch return error.WrongKey;
    const temp = crypto.b2sHmac(&chaining_key, &ephemeral_shared);
    const ck = crypto.b2sHmac(&temp, &[_]u8{0x01});
    const key = crypto.b2sHmac2(&temp, &ck, &[_]u8{0x02});

    var peer_static_public: [KEY_LEN]u8 = undefined;
    crypto.aeadChaCha20Open(&peer_static_public, key, 0, packet.encrypted_static, &hash) catch return error.InvalidAeadTag;

    return .{
        .peer_index = peer_index,
        .peer_static_public = peer_static_public,
    };
}

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "INITIAL_CHAIN_KEY comptime verification" {
    const expected = [_]u8{
        96, 226, 109, 174, 243, 39,  239, 192, 46, 195, 53,  226, 160, 37,  210, 208,
        22, 235, 66,  6,   248, 114, 119, 245, 45, 56,  209, 152, 139, 120, 205, 54,
    };
    try testing.expectEqualSlices(u8, &expected, &INITIAL_CHAIN_KEY);
}

test "INITIAL_CHAIN_HASH comptime verification" {
    const expected = [_]u8{
        34, 17,  179, 97,  8,  26,  197, 102, 105, 18,  67,  219, 69,  138, 213, 50,
        45, 156, 108, 102, 34, 147, 232, 183, 14,  225, 156, 101, 186, 7,   158, 243,
    };
    try testing.expectEqualSlices(u8, &expected, &INITIAL_CHAIN_HASH);
}

test "full handshake round-trip" {
    const now: i128 = std.time.nanoTimestamp();

    // Generate key pairs
    const initiator_kp = crypto.x25519KeyPairGenerate();
    const responder_kp = crypto.x25519KeyPairGenerate();

    // Create handshake instances
    var initiator = Handshake.init(
        initiator_kp.secret_key,
        initiator_kp.public_key,
        responder_kp.public_key,
        Index.newLocal(1),
        null,
        now,
    );
    var responder = Handshake.init(
        responder_kp.secret_key,
        responder_kp.public_key,
        initiator_kp.public_key,
        Index.newLocal(2),
        null,
        now,
    );

    // Step 1: Initiator creates handshake init
    var init_buf: [HANDSHAKE_INIT_SZ]u8 = undefined;
    const init_result = try initiator.formatHandshakeInitiation(&init_buf, now);

    // Parse the init packet
    const init_packet = HandshakeInit{
        .sender_idx = std.mem.readInt(u32, init_result.packet[4..8], .little),
        .unencrypted_ephemeral = init_result.packet[8..40],
        .encrypted_static = init_result.packet[40..88],
        .encrypted_timestamp = init_result.packet[88..116],
    };

    // Step 2: Responder processes init and creates response
    var resp_buf: [HANDSHAKE_RESP_SZ]u8 = undefined;
    const resp_result = try responder.receiveHandshakeInitialization(init_packet, &resp_buf, now + 1000);

    // Parse the response packet
    const resp_packet = HandshakeResponse{
        .sender_idx = std.mem.readInt(u32, resp_result.packet[4..8], .little),
        .receiver_idx = std.mem.readInt(u32, resp_result.packet[8..12], .little),
        .unencrypted_ephemeral = resp_result.packet[12..44],
        .encrypted_nothing = resp_result.packet[44..60],
    };

    // Step 3: Initiator processes response and establishes session
    const initiator_session = try initiator.receiveHandshakeResponse(resp_packet, now + 2000);

    // Step 4: Verify sessions can encrypt/decrypt
    var responder_session = resp_result.session;

    const plaintext = "Hello, WireGuard!";
    const overhead = @import("session.zig").DATA_OVERHEAD_SZ;
    var packet_buf: [plaintext.len + overhead]u8 = undefined;
    const encrypted = try responder_session.formatPacketData(plaintext, &packet_buf);

    // Parse and decrypt
    const data_packet = @import("session.zig").PacketData{
        .receiver_idx = std.mem.readInt(u32, encrypted[4..8], .little),
        .counter = std.mem.readInt(u64, encrypted[8..16], .little),
        .encrypted_encapsulated_packet = encrypted[16..],
    };

    var initiator_session_mut = initiator_session;
    var decrypt_buf: [plaintext.len + 16]u8 = undefined;
    const decrypted = try initiator_session_mut.receivePacketData(data_packet, &decrypt_buf);
    try testing.expectEqualSlices(u8, plaintext, decrypted);
}
