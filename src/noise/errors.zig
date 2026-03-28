// Copyright (c) 2024 Ziguard contributors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
//
// Ported from boringtun (Cloudflare, Inc.; Firezone fork)

pub const WireGuardError = error{
    DestinationBufferTooSmall,
    UnexpectedPacket,
    WrongIndex,
    WrongKey,
    InvalidTai64nTimestamp,
    WrongTai64nTimestamp,
    InvalidMac,
    InvalidAeadTag,
    InvalidCounter,
    DuplicateCounter,
    InvalidPacket,
    NoCurrentSession,
    ConnectionExpired,
    UnderLoad,
};
