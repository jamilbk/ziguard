// Copyright (c) 2024 Ziguard contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
//
// macOS utun TUN device implementation.
// Ported from boringtun (Cloudflare, Inc.; Firezone fork)

const std = @import("std");
const posix = std.posix;
const c = std.c;

// Darwin-specific constants for utun socket creation.
const PF_SYSTEM: u32 = 32;
const SYSPROTO_CONTROL: u32 = 2;
const AF_SYS_CONTROL: u16 = 2;
const AF_SYSTEM: u8 = 32;
// ioctl request codes (unsigned on Darwin, but we store as the raw u32 bit pattern)
const CTLIOCGINFO: u32 = 0xc0644e03;
const SIOCGIFMTU: u32 = 0xc0206933;

// Darwin ioctl uses unsigned long for the request code. ioctl takes c_int,
// which cannot represent these high-bit-set values. Declare our own extern binding.
extern "c" fn ioctl(fd: c_int, request: c_ulong, ...) c_int;
const UTUN_OPT_IFNAME: u32 = 2;
const UTUN_CONTROL_NAME = "com.apple.net.utun_control";

const AF_INET: u32 = 2;
const AF_INET6: u32 = 30;

const SOCK_DGRAM: u32 = 2;
const SYSPROTO_EVENT: u32 = 1;

// ctl_info: used with CTLIOCGINFO ioctl to resolve a kernel control name to its ID.
const CtlInfo = extern struct {
    ctl_id: u32,
    ctl_name: [96]u8,
};

// sockaddr_ctl: used to connect to a kernel control socket.
const SockaddrCtl = extern struct {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [5]u32,
};

// ifreq for SIOCGIFMTU — we only need the name and the mtu field from the union.
const IfMtuReq = extern struct {
    ifr_name: [16]u8,
    ifr_mtu: i32,
    _pad: [20]u8,
};

/// Parse a utun interface name and return the unit number for sockaddr_ctl.
/// "utun" maps to unit 1 (index 0 + 1), "utun3" maps to unit 4 (index 3 + 1).
/// Returns error.InvalidName if the name does not start with "utun" or has a
/// non-numeric suffix.
pub fn parseUtunName(name: []const u8) !u32 {
    if (name.len < 4) return error.InvalidName;
    if (!std.mem.eql(u8, name[0..4], "utun")) return error.InvalidName;

    const suffix = name[4..];
    if (suffix.len == 0) {
        // "utun" alone means unit index 0 => unit number 1
        return 1;
    }

    const index = std.fmt.parseInt(u32, suffix, 10) catch return error.InvalidName;
    return index + 1;
}

pub const TunSocket = struct {
    handle: posix.fd_t,

    /// Create a new TUN socket bound to the named utun interface.
    pub fn init(name: []const u8) !TunSocket {
        const unit = try parseUtunName(name);

        // Create PF_SYSTEM socket with SYSPROTO_CONTROL.
        const raw_fd = try posix.socket(PF_SYSTEM, posix.SOCK.DGRAM, SYSPROTO_CONTROL);
        errdefer posix.close(raw_fd);

        // Resolve the control ID for UTUN_CONTROL_NAME via CTLIOCGINFO.
        var info: CtlInfo = std.mem.zeroes(CtlInfo);
        const ctrl_name = UTUN_CONTROL_NAME;
        @memcpy(info.ctl_name[0..ctrl_name.len], ctrl_name);

        const ioctl_ret = ioctl(@intCast(raw_fd), CTLIOCGINFO, &info);
        if (ioctl_ret < 0) {
            return error.IoctlFailed;
        }

        // Connect with sockaddr_ctl to bind to the specific utun unit.
        var addr: SockaddrCtl = std.mem.zeroes(SockaddrCtl);
        addr.sc_len = @sizeOf(SockaddrCtl);
        addr.sc_family = AF_SYSTEM;
        addr.ss_sysaddr = AF_SYS_CONTROL;
        addr.sc_id = info.ctl_id;
        addr.sc_unit = unit;

        const sa_ptr: *const posix.sockaddr = @ptrCast(&addr);
        try posix.connect(raw_fd, sa_ptr, @sizeOf(SockaddrCtl));

        return .{ .handle = raw_fd };
    }

    /// Close the underlying file descriptor.
    pub fn deinit(self: *TunSocket) void {
        posix.close(self.handle);
        self.handle = -1;
    }

    /// Set the socket to non-blocking mode.
    pub fn setNonBlocking(self: *TunSocket) !void {
        const flags = try posix.fcntl(self.handle, posix.F.GETFL, @as(usize, 0));
        // O_NONBLOCK is bit 2 (0x4) on Darwin
        _ = try posix.fcntl(self.handle, posix.F.SETFL, flags | 0x4);
    }

    /// Retrieve the interface name assigned by the kernel.
    /// Writes into the provided buffer and returns a slice of the actual name.
    pub fn getName(self: *const TunSocket, buf: *[256]u8) ![]const u8 {
        var buf_len: posix.socklen_t = buf.len;
        const rc = std.c.getsockopt(
            self.handle,
            SYSPROTO_CONTROL,
            @intCast(UTUN_OPT_IFNAME),
            buf,
            &buf_len,
        );
        if (rc < 0) {
            return error.GetSockOptFailed;
        }
        // buf_len includes the null terminator; return without it.
        if (buf_len > 0) buf_len -= 1;
        return buf[0..buf_len];
    }

    /// Query the MTU of this TUN interface.
    pub fn mtu(self: *const TunSocket) !usize {
        var name_buf: [256]u8 = undefined;
        const iface_name = try self.getName(&name_buf);

        var req: IfMtuReq = std.mem.zeroes(IfMtuReq);
        @memcpy(req.ifr_name[0..iface_name.len], iface_name);

        // Use a temporary UDP socket for the SIOCGIFMTU ioctl.
        const tmp_fd = try posix.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
        defer posix.close(tmp_fd);

        const ret = ioctl(@intCast(tmp_fd), SIOCGIFMTU, &req);
        if (ret < 0) {
            return error.IoctlFailed;
        }

        return @intCast(req.ifr_mtu);
    }

    /// Write an IPv4 packet to the TUN device.
    /// The 4-byte AF_INET header is prepended automatically.
    /// Returns the number of payload bytes written (excluding the header),
    /// or 0 on error.
    pub fn write4(self: *const TunSocket, src: []const u8) usize {
        return self.writeWithHeader(AF_INET, src);
    }

    /// Write an IPv6 packet to the TUN device.
    /// The 4-byte AF_INET6 header is prepended automatically.
    /// Returns the number of payload bytes written (excluding the header),
    /// or 0 on error.
    pub fn write6(self: *const TunSocket, src: []const u8) usize {
        return self.writeWithHeader(AF_INET6, src);
    }

    fn writeWithHeader(self: *const TunSocket, af: u32, src: []const u8) usize {
        const hdr = std.mem.toBytes(std.mem.nativeToBig(u32, af));

        const iov = [2]posix.iovec_const{
            .{ .base = &hdr, .len = hdr.len },
            .{ .base = src.ptr, .len = src.len },
        };

        var msg: std.posix.msghdr_const = std.mem.zeroes(std.posix.msghdr_const);
        msg.iov = &iov;
        msg.iovlen = iov.len;

        const sent = posix.sendmsg(self.handle, &msg, 0) catch return 0;
        if (sent <= 4) return 0;
        return sent - 4;
    }

    /// Read a packet from the TUN device.
    /// The 4-byte protocol header is consumed internally; the returned slice
    /// contains only the IP payload within `dst`.
    pub fn read(self: *const TunSocket, dst: []u8) ![]u8 {
        if (dst.len < 4) return error.BufferTooSmall;

        const n = posix.read(self.handle, dst) catch |err| return err;

        if (n < 4) return error.ShortRead;

        // Shift the payload left by 4 bytes, overwriting the AF header.
        const payload_len = n - 4;
        std.mem.copyForwards(u8, dst[0..payload_len], dst[4..n]);
        return dst[0..payload_len];
    }

    /// Return the raw file descriptor for use with poll/epoll/kqueue.
    pub fn fd(self: *const TunSocket) posix.fd_t {
        return self.handle;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parseUtunName: bare utun is unit 1" {
    const unit = try parseUtunName("utun");
    try std.testing.expectEqual(@as(u32, 1), unit);
}

test "parseUtunName: utun0 is unit 1" {
    const unit = try parseUtunName("utun0");
    try std.testing.expectEqual(@as(u32, 1), unit);
}

test "parseUtunName: utun3 is unit 4" {
    const unit = try parseUtunName("utun3");
    try std.testing.expectEqual(@as(u32, 4), unit);
}

test "parseUtunName: utun42 is unit 43" {
    const unit = try parseUtunName("utun42");
    try std.testing.expectEqual(@as(u32, 43), unit);
}

test "parseUtunName: rejects empty string" {
    try std.testing.expectError(error.InvalidName, parseUtunName(""));
}

test "parseUtunName: rejects non-utun prefix" {
    try std.testing.expectError(error.InvalidName, parseUtunName("tun0"));
}

test "parseUtunName: rejects invalid suffix" {
    try std.testing.expectError(error.InvalidName, parseUtunName("utunABC"));
}

test "parseUtunName: rejects negative index" {
    try std.testing.expectError(error.InvalidName, parseUtunName("utun-1"));
}
