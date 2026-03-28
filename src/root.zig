// Copyright (c) 2024 Ziguard contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
//
// Ziguard: A WireGuard implementation in Zig.
// Ported from boringtun (Cloudflare, Inc.; Firezone fork)

pub const crypto = @import("crypto.zig");
pub const noise = @import("noise/noise.zig");
pub const Tai64N = @import("tai64n.zig").Tai64N;
pub const TimeStamper = @import("tai64n.zig").TimeStamper;
pub const serialization = @import("serialization.zig");

test {
    _ = crypto;
    _ = @import("noise/errors.zig");
    _ = @import("tai64n.zig");
    _ = @import("noise/index.zig");
    _ = @import("noise/session.zig");
    _ = @import("noise/handshake.zig");
    _ = @import("noise/timers.zig");
    _ = @import("noise/rate_limiter.zig");
    _ = @import("noise/tunnel.zig");
    _ = serialization;
    _ = @import("device/tun_darwin.zig");
    _ = @import("device/allowed_ips.zig");
}
