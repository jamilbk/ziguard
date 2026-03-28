# Ziguard

A WireGuard implementation in Zig, ported from [boringtun](https://github.com/cloudflare/boringtun) ([Firezone fork](https://github.com/firezone/boringtun)). Zero external dependencies — uses only Zig's standard library.

## Requirements

- Zig 0.15.x
- macOS (utun support) or Linux

## Build

```sh
zig build
```

This produces both a library (`zig-out/lib/libziguard.a`) and a CLI binary (`zig-out/bin/ziguard`).

## Test

```sh
zig build test
```

Show individual test names and timing:

```sh
zig build test --summary all
```

## Running (macOS)

Generate a keypair using `wg` (from wireguard-tools) or any WireGuard key generator:

```sh
wg genkey | tee private.key | wg pubkey > public.key
```

Start the tunnel (requires root for utun access):

```sh
sudo zig-out/bin/ziguard \
  --private-key $(cat private.key) \
  --peer-public-key <PEER_PUBLIC_KEY> \
  --endpoint <PEER_IP>:<PEER_PORT> \
  --allowed-ips 10.0.0.0/24 \
  --listen-port 51820 \
  --tun utun
```

Then configure the interface address and routing:

```sh
sudo ifconfig utun7 10.0.0.2/24 10.0.0.1
sudo route add -net 10.0.0.0/24 -interface utun7
```

(Replace `utun7` with the actual interface name printed at startup.)

### CLI Options

```
Required:
  --private-key <base64>       Local private key
  --peer-public-key <base64>   Peer's public key
  --endpoint <ip:port>         Peer endpoint address
  --allowed-ips <cidr>         Comma-separated CIDR list (e.g. 10.0.0.0/24,0.0.0.0/0)

Optional:
  --listen-port <port>         UDP listen port (default: random)
  --tun <name>                 TUN interface name (default: utun)
  --keepalive <seconds>        Persistent keepalive interval
  --preshared-key <base64>     Preshared key for additional security
  --help                       Show this help
```

Press Ctrl+C to stop the tunnel.

## Project Structure

```
src/
├── main.zig              # CLI entry point
├── root.zig              # Library entry point
├── crypto.zig            # Crypto wrappers (X25519, ChaCha20Poly1305, BLAKE2s, HMAC)
├── tai64n.zig            # TAI64N timestamps
├── serialization.zig     # Base64/hex key encoding/decoding
├── noise/
│   ├── noise.zig         # Module re-exports
│   ├── errors.zig        # WireGuard error types
│   ├── index.zig         # Session index management
│   ├── session.zig       # Session encrypt/decrypt + replay prevention
│   ├── handshake.zig     # Noise IKpsk2 handshake protocol
│   ├── timers.zig        # Rekey/keepalive timer management
│   ├── rate_limiter.zig  # Cookie-based DoS prevention
│   └── tunnel.zig        # Tunnel state machine (encap/decap, handshake flow)
└── device/
    ├── device.zig        # Device event loop (poll-based)
    ├── peer.zig          # Peer state management
    ├── tun_darwin.zig    # macOS utun TUN device
    └── allowed_ips.zig   # IP routing table (CIDR trie)
```

## Library Usage

Ziguard also builds as a library. Import it from your Zig project:

```zig
const ziguard = @import("ziguard");
const Tunn = ziguard.noise.Tunn;
const serialization = ziguard.serialization;

// Parse a base64-encoded private key
const private_key = try serialization.parseKey("BASE64_ENCODED_KEY_HERE==");

// Derive public key
const public_key = try ziguard.crypto.x25519PublicKey(private_key);

// Create a tunnel to a peer
var tunnel = Tunn.init(
    allocator,
    private_key,
    peer_public_key,
    null,  // preshared key (optional)
    null,  // persistent keepalive interval (optional)
    0,     // peer index
    std.time.nanoTimestamp(),
);
defer tunnel.deinit();

// Encapsulate an outbound IP packet
var dst: [2048]u8 = undefined;
const result = tunnel.encapsulateAt(ip_packet, &dst, std.time.nanoTimestamp());
switch (result) {
    .write_to_network => |data| {
        // Send `data` as a UDP datagram to the peer
    },
    .err => |e| std.debug.print("error: {}\n", .{e}),
    else => {},
}

// Decapsulate an inbound UDP datagram
var plain: [2048]u8 = undefined;
const recv = tunnel.decapsulateAt(null, udp_payload, &plain, std.time.nanoTimestamp());
switch (recv) {
    .write_to_tunnel_v4 => |info| {
        // Write `info.packet` to the TUN device
    },
    .write_to_network => |data| {
        // Handshake/keepalive response — send back to peer
    },
    else => {},
}
```

## Cryptography

All crypto is provided by Zig's `std.crypto`:

| Primitive          | Zig path                                        |
| ------------------ | ----------------------------------------------- |
| X25519             | `std.crypto.dh.X25519`                          |
| ChaCha20-Poly1305  | `std.crypto.aead.chacha_poly.ChaCha20Poly1305`  |
| XChaCha20-Poly1305 | `std.crypto.aead.chacha_poly.XChaCha20Poly1305` |
| BLAKE2s            | `std.crypto.hash.blake2.Blake2s256`             |
| HMAC-BLAKE2s       | `std.crypto.auth.hmac.Hmac(Blake2s256)`         |

## License

BSD-3-Clause
