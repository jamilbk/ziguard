// Copyright (c) 2024 Ziguard contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
//
// WireGuard timer management.
// Ported from boringtun (Cloudflare, Inc.; Firezone fork)

const std = @import("std");

// Timer constants (nanoseconds)
pub const REKEY_AFTER_TIME: i128 = 120 * std.time.ns_per_s;
pub const REJECT_AFTER_TIME: i128 = 180 * std.time.ns_per_s;
pub const REKEY_ATTEMPT_TIME: i128 = 90 * std.time.ns_per_s;
pub const REKEY_TIMEOUT: i128 = 5 * std.time.ns_per_s;
pub const KEEPALIVE_TIMEOUT: i128 = 10 * std.time.ns_per_s;
pub const COOKIE_EXPIRATION_TIME: i128 = 120 * std.time.ns_per_s;
pub const MAX_JITTER: i128 = 333 * std.time.ns_per_ms;

pub const SHOULD_NOT_USE_AFTER_TIME: i128 = REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT;

pub const TimerName = enum(usize) {
    time_session_established = 0,
    time_last_handshake_started = 1,
    time_last_packet_received = 2,
    time_last_packet_sent = 3,
    time_last_data_packet_received = 4,
    time_last_data_packet_sent = 5,
    time_persistent_keepalive = 6,
    time_last_update = 7,
    top = 8,
};

pub const Timers = struct {
    is_initiator: bool = false,
    timer_values: [@intFromEnum(TimerName.top)]i128,
    want_passive_keepalive_at: ?i128 = null,
    want_handshake_at: ?i128 = null,
    persistent_keepalive: usize = 0,
    should_reset_rr: bool = false,
    send_handshake_at: ?i128 = null,
    jitter_prng: std.Random.DefaultPrng,
    rekey_attempt_time: i128 = REKEY_ATTEMPT_TIME,

    pub fn init(persistent_keepalive: ?u16, reset_rr: bool, rng_seed: u64, now: i128) Timers {
        return .{
            .timer_values = [_]i128{now} ** @intFromEnum(TimerName.top),
            .persistent_keepalive = if (persistent_keepalive) |pk| @as(usize, pk) else 0,
            .should_reset_rr = reset_rr,
            .jitter_prng = std.Random.DefaultPrng.init(rng_seed),
        };
    }

    pub fn get(self: *const Timers, name: TimerName) i128 {
        return self.timer_values[@intFromEnum(name)];
    }

    pub fn set(self: *Timers, name: TimerName, value: i128) void {
        self.timer_values[@intFromEnum(name)] = value;
    }

    pub fn clear(self: *Timers, now: i128) void {
        for (&self.timer_values) |*t| {
            t.* = now;
        }
        self.want_handshake_at = null;
        self.want_passive_keepalive_at = null;
    }

    pub fn setRekeyAttemptTime(self: *Timers, time_ns: i128) void {
        self.rekey_attempt_time = time_ns;
    }

    pub fn getJitter(self: *Timers) i128 {
        const random = self.jitter_prng.random();
        const jitter_ms = random.intRangeAtMost(u32, 0, 333);
        return @as(i128, jitter_ms) * std.time.ns_per_ms;
    }
};
