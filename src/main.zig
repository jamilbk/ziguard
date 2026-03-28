// Copyright (c) 2024 Ziguard contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
//
// Ziguard CLI — a userspace WireGuard implementation for macOS.
// Usage:
//   sudo ziguard --private-key <base64> --peer-public-key <base64> \
//     --endpoint <ip:port> --allowed-ips <cidr> [--listen-port <port>] \
//     [--tun <utunN>] [--keepalive <seconds>] [--preshared-key <base64>]

const std = @import("std");
const Device = @import("device/device.zig").Device;
const AllowedIP = @import("device/peer.zig").AllowedIP;
const serialization = @import("serialization.zig");

const usage =
    \\Usage: ziguard [options]
    \\
    \\Required:
    \\  --private-key <base64>       Local private key
    \\  --peer-public-key <base64>   Peer's public key
    \\  --endpoint <ip:port>         Peer endpoint address
    \\  --allowed-ips <cidr>         Comma-separated CIDR list (e.g. 10.0.0.0/24,0.0.0.0/0)
    \\
    \\Optional:
    \\  --listen-port <port>         UDP listen port (default: random)
    \\  --tun <name>                 TUN interface name (default: utun)
    \\  --keepalive <seconds>        Persistent keepalive interval
    \\  --preshared-key <base64>     Preshared key for additional security
    \\  --help                       Show this help
    \\
;

fn log(comptime fmt: []const u8, args: anytype) void {
    std.debug.print(fmt ++ "\n", args);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var private_key_str: ?[]const u8 = null;
    var peer_public_key_str: ?[]const u8 = null;
    var endpoint_str: ?[]const u8 = null;
    var allowed_ips_str: ?[]const u8 = null;
    var listen_port: u16 = 0;
    var tun_name: []const u8 = "utun";
    var keepalive: ?u16 = null;
    var preshared_key_str: ?[]const u8 = null;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            std.debug.print("{s}", .{usage});
            return;
        } else if (std.mem.eql(u8, arg, "--private-key")) {
            i += 1;
            if (i >= args.len) return fatal("--private-key requires a value");
            private_key_str = args[i];
        } else if (std.mem.eql(u8, arg, "--peer-public-key")) {
            i += 1;
            if (i >= args.len) return fatal("--peer-public-key requires a value");
            peer_public_key_str = args[i];
        } else if (std.mem.eql(u8, arg, "--endpoint")) {
            i += 1;
            if (i >= args.len) return fatal("--endpoint requires a value");
            endpoint_str = args[i];
        } else if (std.mem.eql(u8, arg, "--allowed-ips")) {
            i += 1;
            if (i >= args.len) return fatal("--allowed-ips requires a value");
            allowed_ips_str = args[i];
        } else if (std.mem.eql(u8, arg, "--listen-port")) {
            i += 1;
            if (i >= args.len) return fatal("--listen-port requires a value");
            listen_port = std.fmt.parseInt(u16, args[i], 10) catch return fatal("Invalid port number");
        } else if (std.mem.eql(u8, arg, "--tun")) {
            i += 1;
            if (i >= args.len) return fatal("--tun requires a value");
            tun_name = args[i];
        } else if (std.mem.eql(u8, arg, "--keepalive")) {
            i += 1;
            if (i >= args.len) return fatal("--keepalive requires a value");
            keepalive = std.fmt.parseInt(u16, args[i], 10) catch return fatal("Invalid keepalive interval");
        } else if (std.mem.eql(u8, arg, "--preshared-key")) {
            i += 1;
            if (i >= args.len) return fatal("--preshared-key requires a value");
            preshared_key_str = args[i];
        } else {
            log("Unknown argument: {s}", .{arg});
            std.debug.print("{s}", .{usage});
            std.process.exit(1);
        }
    }

    // Validate required args
    const priv_key_s = private_key_str orelse return fatal("--private-key is required");
    const peer_pub_s = peer_public_key_str orelse return fatal("--peer-public-key is required");
    const ep_str = endpoint_str orelse return fatal("--endpoint is required");
    const aips_str = allowed_ips_str orelse return fatal("--allowed-ips is required");

    // Parse keys
    const private_key = serialization.parseKey(priv_key_s) catch return fatal("Invalid private key");
    const peer_public_key = serialization.parseKey(peer_pub_s) catch return fatal("Invalid peer public key");

    var preshared_key: ?[32]u8 = null;
    if (preshared_key_str) |psk_s| {
        preshared_key = serialization.parseKey(psk_s) catch return fatal("Invalid preshared key");
    }

    // Parse endpoint
    const endpoint = parseEndpoint(ep_str) catch return fatal("Invalid endpoint (expected ip:port)");

    // Parse allowed IPs
    var allowed_ips_list: std.ArrayList(AllowedIP) = .{};
    defer allowed_ips_list.deinit(allocator);
    var cidr_iter = std.mem.splitScalar(u8, aips_str, ',');
    while (cidr_iter.next()) |cidr_str| {
        const trimmed = std.mem.trim(u8, cidr_str, " ");
        if (trimmed.len == 0) continue;
        const aip = parseCidr(trimmed) catch return fatal("Invalid CIDR in --allowed-ips");
        try allowed_ips_list.append(allocator, aip);
    }

    // Create device
    const device = Device.init(allocator, .{
        .private_key = private_key,
        .listen_port = listen_port,
        .tun_name = tun_name,
    }) catch |err| {
        log("Failed to create device: {}", .{err});
        log("(Did you run with sudo?)", .{});
        std.process.exit(1);
    };

    // Register signal handler for clean shutdown
    const handler = struct {
        var dev: *Device = undefined;
        fn handle(_: c_int) callconv(.c) void {
            dev.stop();
        }
    };
    handler.dev = device;
    const act = std.posix.Sigaction{
        .handler = .{ .handler = handler.handle },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &act, null);
    std.posix.sigaction(std.posix.SIG.TERM, &act, null);

    // Add peer
    try device.addPeer(.{
        .public_key = peer_public_key,
        .preshared_key = preshared_key,
        .endpoint = endpoint,
        .allowed_ips = allowed_ips_list.items,
        .persistent_keepalive = keepalive,
    });

    const pub_key_b64 = serialization.keyToBase64(&device.public_key);
    log("Public key: {s}", .{pub_key_b64});

    // Run event loop (blocks until SIGINT/SIGTERM)
    try device.run();

    device.deinit();
}

fn fatal(msg: []const u8) void {
    std.debug.print("{s}\n", .{msg});
    std.process.exit(1);
}

fn parseEndpoint(s: []const u8) !std.net.Address {
    const colon_idx = std.mem.lastIndexOfScalar(u8, s, ':') orelse return error.InvalidEndpoint;
    const ip_str = s[0..colon_idx];
    const port_str = s[colon_idx + 1 ..];
    const port = std.fmt.parseInt(u16, port_str, 10) catch return error.InvalidEndpoint;

    return std.net.Address.parseIp4(ip_str, port) catch {
        return std.net.Address.parseIp6(ip_str, port) catch return error.InvalidEndpoint;
    };
}

fn parseCidr(s: []const u8) !AllowedIP {
    const slash_idx = std.mem.indexOfScalar(u8, s, '/') orelse return error.InvalidCidr;
    const ip_str = s[0..slash_idx];
    const cidr_str = s[slash_idx + 1 ..];
    const cidr = std.fmt.parseInt(u8, cidr_str, 10) catch return error.InvalidCidr;

    if (std.net.Address.parseIp4(ip_str, 0)) |addr| {
        const bytes = @as(*const [4]u8, @ptrCast(&addr.in.sa.addr));
        if (cidr > 32) return error.InvalidCidr;
        return .{ .addr = .{ .v4 = bytes.* }, .cidr = cidr };
    } else |_| {}

    if (std.net.Address.parseIp6(ip_str, 0)) |addr| {
        if (cidr > 128) return error.InvalidCidr;
        return .{ .addr = .{ .v6 = addr.in6.sa.addr }, .cidr = cidr };
    } else |_| {}

    return error.InvalidCidr;
}
