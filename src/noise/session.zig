// Copyright (c) 2024 Ziguard contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
//
// WireGuard session encryption/decryption with replay prevention.
// Ported from boringtun (Cloudflare, Inc.; Firezone fork)

const std = @import("std");
const crypto = @import("../crypto.zig");
const Index = @import("index.zig").Index;
const WireGuardError = @import("errors.zig").WireGuardError;

/// WireGuard packet type for data
pub const DATA: u32 = 4;
/// Header: 4 (type) + 4 (receiver index) + 8 (counter) = 16 bytes
const DATA_OFFSET: usize = 16;
/// AEAD tag overhead
const AEAD_SIZE: usize = 16;
/// Total overhead: header + AEAD tag
pub const DATA_OVERHEAD_SZ: usize = DATA_OFFSET + AEAD_SIZE;

/// Timer constants (seconds -> nanoseconds)
pub const REJECT_AFTER_TIME: i128 = 180 * std.time.ns_per_s;
pub const SHOULD_NOT_USE_AFTER_TIME: i128 = (180 - 10) * std.time.ns_per_s; // REJECT - KEEPALIVE

// Replay prevention constants
const WORD_SIZE: u64 = 64;
const N_WORDS: u64 = 128; // 128 * 64 = 8192 packets reorder window
const N_BITS: u64 = WORD_SIZE * N_WORDS;

/// A parsed data packet from the network.
pub const PacketData = struct {
    receiver_idx: u32,
    counter: u64,
    encrypted_encapsulated_packet: []const u8,
};

/// Validates received packet counters to prevent replay attacks.
/// Uses a sliding window bitmap to allow some reordering while rejecting duplicates.
pub const ReceivingKeyCounterValidator = struct {
    next: u64 = 0,
    receive_cnt: u64 = 0,
    bitmap: [N_WORDS]u64 = [_]u64{0} ** N_WORDS,

    fn setBit(self: *ReceivingKeyCounterValidator, idx: u64) void {
        const bit_idx = idx % N_BITS;
        const word: usize = @intCast(bit_idx / WORD_SIZE);
        const bit: u6 = @intCast(bit_idx % WORD_SIZE);
        self.bitmap[word] |= @as(u64, 1) << bit;
    }

    fn clearBit(self: *ReceivingKeyCounterValidator, idx: u64) void {
        const bit_idx = idx % N_BITS;
        const word: usize = @intCast(bit_idx / WORD_SIZE);
        const bit: u6 = @intCast(bit_idx % WORD_SIZE);
        self.bitmap[word] &= ~(@as(u64, 1) << bit);
    }

    fn clearWord(self: *ReceivingKeyCounterValidator, idx: u64) void {
        const bit_idx = idx % N_BITS;
        const word: usize = @intCast(bit_idx / WORD_SIZE);
        self.bitmap[word] = 0;
    }

    fn checkBit(self: *const ReceivingKeyCounterValidator, idx: u64) bool {
        const bit_idx = idx % N_BITS;
        const word: usize = @intCast(bit_idx / WORD_SIZE);
        const bit: u6 = @intCast(bit_idx % WORD_SIZE);
        return ((self.bitmap[word] >> bit) & 1) == 1;
    }

    /// Returns error if the counter was already received or is too far back.
    pub fn willAccept(self: *const ReceivingKeyCounterValidator, counter: u64) WireGuardError!void {
        if (counter >= self.next) {
            return; // Growing counter, no replay
        }
        if (counter + N_BITS < self.next) {
            return error.InvalidCounter; // Too far back
        }
        if (!self.checkBit(counter)) {
            return; // Not yet seen
        }
        return error.DuplicateCounter;
    }

    /// Marks the counter as received. Returns error if it's a duplicate or too old.
    pub fn markDidReceive(self: *ReceivingKeyCounterValidator, counter: u64) WireGuardError!void {
        if (counter + N_BITS < self.next) {
            return error.InvalidCounter;
        }
        if (counter == self.next) {
            // In-order packet: mark and increment
            self.setBit(counter);
            self.next += 1;
            return;
        }
        if (counter < self.next) {
            // Out-of-order but within window
            if (self.checkBit(counter)) {
                return error.DuplicateCounter;
            }
            self.setBit(counter);
            return;
        }
        // Packets were dropped or reordered; skip ahead
        if (counter - self.next >= N_BITS) {
            // Too far ahead, clear all bits
            @memset(&self.bitmap, 0);
        } else {
            var i = self.next;
            // Clear until aligned to word size
            while (i % WORD_SIZE != 0 and i < counter) {
                self.clearBit(i);
                i += 1;
            }
            // Clear whole words at a time
            while (i + WORD_SIZE < counter) {
                self.clearWord(i);
                i = (i + WORD_SIZE) & (0 -% WORD_SIZE);
            }
            // Clear remaining bits
            while (i < counter) {
                self.clearBit(i);
                i += 1;
            }
        }
        self.setBit(counter);
        self.next = counter + 1;
    }
};

/// An established WireGuard session with encryption keys.
pub const Session = struct {
    established_at: i128, // monotonic nanosecond timestamp
    receiving_index: Index,
    sending_index: Index,
    receiving_key: [32]u8,
    sending_key: [32]u8,
    sending_key_counter: std.atomic.Value(u64),
    receiving_key_counter: ReceivingKeyCounterValidator,
    receiving_key_counter_lock: std.Thread.Mutex,

    pub fn init(
        local_index: Index,
        peer_index: Index,
        receiving_key: [32]u8,
        sending_key: [32]u8,
        now: i128,
    ) Session {
        return .{
            .established_at = now,
            .receiving_index = local_index,
            .sending_index = peer_index,
            .receiving_key = receiving_key,
            .sending_key = sending_key,
            .sending_key_counter = std.atomic.Value(u64).init(0),
            .receiving_key_counter = .{},
            .receiving_key_counter_lock = .{},
        };
    }

    pub fn localIndex(self: *const Session) Index {
        return self.receiving_index;
    }

    pub fn establishedAt(self: *const Session) i128 {
        return self.established_at;
    }

    pub fn expiredAt(self: *const Session, time: i128) bool {
        return time > self.established_at + REJECT_AFTER_TIME;
    }

    pub fn shouldUseAt(self: *const Session, time: i128) bool {
        return time <= self.established_at + SHOULD_NOT_USE_AFTER_TIME;
    }

    fn receivingCounterQuickCheck(self: *Session, counter: u64) WireGuardError!void {
        self.receiving_key_counter_lock.lock();
        defer self.receiving_key_counter_lock.unlock();
        try self.receiving_key_counter.willAccept(counter);
    }

    fn receivingCounterMark(self: *Session, counter: u64) WireGuardError!void {
        self.receiving_key_counter_lock.lock();
        defer self.receiving_key_counter_lock.unlock();
        try self.receiving_key_counter.markDidReceive(counter);
        self.receiving_key_counter.receive_cnt += 1;
    }

    /// Encrypt an IP packet into a WireGuard data packet.
    /// `src` is the plaintext IP packet.
    /// `dst` is the output buffer (must be at least src.len + DATA_OVERHEAD_SZ).
    /// Returns the slice of `dst` containing the formatted packet.
    pub fn formatPacketData(self: *Session, src: []const u8, dst: []u8) WireGuardError![]u8 {
        const num_required = src.len + DATA_OVERHEAD_SZ;
        if (dst.len < num_required) {
            return error.DestinationBufferTooSmall;
        }

        const sending_key_counter = self.sending_key_counter.fetchAdd(1, .monotonic);

        // Write header
        const type_bytes = std.mem.toBytes(std.mem.nativeToLittle(u32, DATA));
        @memcpy(dst[0..4], &type_bytes);
        @memcpy(dst[4..8], &self.sending_index.toLeBytes());
        const counter_bytes = std.mem.toBytes(std.mem.nativeToLittle(u64, sending_key_counter));
        @memcpy(dst[8..16], &counter_bytes);

        // Encrypt: dst[16..] holds ciphertext + tag
        const data = dst[DATA_OFFSET..];
        crypto.aeadChaCha20Seal(data[0 .. src.len + AEAD_SIZE], self.sending_key, sending_key_counter, src, "");

        return dst[0 .. DATA_OFFSET + src.len + AEAD_SIZE];
    }

    /// Decrypt a WireGuard data packet into the encapsulated IP packet.
    /// `packet` is the parsed data packet.
    /// `dst` is the output buffer.
    /// Returns the slice of `dst` containing the decrypted packet.
    pub fn receivePacketData(self: *Session, packet: PacketData, dst: []u8) WireGuardError![]u8 {
        const ct_len = packet.encrypted_encapsulated_packet.len;
        if (dst.len < ct_len) {
            return error.DestinationBufferTooSmall;
        }
        if (!self.receiving_index.eqlU32(packet.receiver_idx)) {
            return error.WrongIndex;
        }

        // Quick check counter before expensive decryption
        try self.receivingCounterQuickCheck(packet.counter);

        // Decrypt
        if (ct_len < AEAD_SIZE) {
            return error.InvalidAeadTag;
        }
        const plaintext_len = ct_len - AEAD_SIZE;
        crypto.aeadChaCha20Open(
            dst[0..plaintext_len],
            self.receiving_key,
            packet.counter,
            packet.encrypted_encapsulated_packet,
            "",
        ) catch return error.InvalidAeadTag;

        // Mark counter as received after successful decryption
        try self.receivingCounterMark(packet.counter);
        return dst[0..plaintext_len];
    }

    /// Returns (next expected counter, total received count) for packet loss estimation.
    pub fn currentPacketCnt(self: *Session) struct { next: u64, receive_cnt: u64 } {
        self.receiving_key_counter_lock.lock();
        defer self.receiving_key_counter_lock.unlock();
        return .{
            .next = self.receiving_key_counter.next,
            .receive_cnt = self.receiving_key_counter.receive_cnt,
        };
    }
};

// ============================================================================
// Tests
// ============================================================================

const testing = std.testing;

test "replay counter basic" {
    var c = ReceivingKeyCounterValidator{};

    try c.markDidReceive(0);
    try testing.expectError(error.DuplicateCounter, c.markDidReceive(0));
    try c.markDidReceive(1);
    try testing.expectError(error.DuplicateCounter, c.markDidReceive(1));
    try c.markDidReceive(63);
    try testing.expectError(error.DuplicateCounter, c.markDidReceive(63));
    try c.markDidReceive(15);
    try testing.expectError(error.DuplicateCounter, c.markDidReceive(15));

    // Sequential range
    var i: u64 = 64;
    while (i < N_BITS + 128) : (i += 1) {
        try c.markDidReceive(i);
        try testing.expectError(error.DuplicateCounter, c.markDidReceive(i));
    }

    // Big jump
    try c.markDidReceive(N_BITS * 3);
    {
        var j: u64 = 0;
        while (j <= N_BITS * 2) : (j += 1) {
            try testing.expectError(error.InvalidCounter, c.willAccept(j));
            try testing.expectError(error.InvalidCounter, c.markDidReceive(j));
        }
    }
    {
        var j: u64 = N_BITS * 2 + 1;
        while (j < N_BITS * 3) : (j += 1) {
            try c.willAccept(j);
        }
    }
    try testing.expectError(error.DuplicateCounter, c.willAccept(N_BITS * 3));

    // Reverse order within window
    {
        var j: u64 = N_BITS * 3 - 1;
        while (j >= N_BITS * 2 + 1) : (j -= 1) {
            try c.markDidReceive(j);
            try testing.expectError(error.DuplicateCounter, c.markDidReceive(j));
            if (j == N_BITS * 2 + 1) break;
        }
    }

    // Mixed jumps
    try c.markDidReceive(N_BITS * 3 + 70);
    try c.markDidReceive(N_BITS * 3 + 71);
    try c.markDidReceive(N_BITS * 3 + 72);
    try c.markDidReceive(N_BITS * 3 + 72 + 125);
    try c.markDidReceive(N_BITS * 3 + 63);

    try testing.expectError(error.DuplicateCounter, c.markDidReceive(N_BITS * 3 + 70));
    try testing.expectError(error.DuplicateCounter, c.markDidReceive(N_BITS * 3 + 71));
    try testing.expectError(error.DuplicateCounter, c.markDidReceive(N_BITS * 3 + 72));
}

test "session encrypt decrypt round-trip" {
    const now: i128 = std.time.nanoTimestamp();
    const local_idx = Index.newLocal(1);
    const peer_idx = Index.newLocal(2);
    const rx_key = [_]u8{0xAA} ** 32;
    const tx_key = [_]u8{0xBB} ** 32;

    var sender = Session.init(local_idx, peer_idx, rx_key, tx_key, now);
    var receiver = Session.init(peer_idx, local_idx, tx_key, rx_key, now);

    const plaintext = "Hello, WireGuard!";
    var packet_buf: [plaintext.len + DATA_OVERHEAD_SZ]u8 = undefined;
    const packet = try sender.formatPacketData(plaintext, &packet_buf);

    // Parse the data packet
    const parsed = PacketData{
        .receiver_idx = std.mem.readInt(u32, packet[4..8], .little),
        .counter = std.mem.readInt(u64, packet[8..16], .little),
        .encrypted_encapsulated_packet = packet[16..],
    };

    var decrypt_buf: [plaintext.len + AEAD_SIZE]u8 = undefined;
    const decrypted = try receiver.receivePacketData(parsed, &decrypt_buf);
    try testing.expectEqualSlices(u8, plaintext, decrypted);
}

test "session expiry" {
    const now: i128 = 0;
    const session = Session.init(Index.newLocal(1), Index.newLocal(2), [_]u8{0} ** 32, [_]u8{0} ** 32, now);

    try testing.expect(!session.expiredAt(now));
    try testing.expect(!session.expiredAt(now + 179 * std.time.ns_per_s));
    try testing.expect(session.expiredAt(now + 181 * std.time.ns_per_s));

    try testing.expect(session.shouldUseAt(now));
    try testing.expect(!session.shouldUseAt(now + 171 * std.time.ns_per_s));
}
