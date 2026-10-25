# Rust Basis Server — Parity Report

## Verified

- Protocol 56 handshake, X25519 key, DID login transcript, HKDF, ChaCha20-Poly1305.
- Connection, authentication, wrong-password/DID rejection, auth timeout, departure.
- Health endpoint, `/api/players`, `/api/worlds` (GET/POST/DELETE/switch), `/api/announce`.
- REST body limit (1 MB / 413), 404/405 with `Allow`, invalid JSON 400, strategy validation,
  URL/password/fragment (Base64) validation, UTF-16 message length, world delete semantics,
  switch `announceMessage`/`delay` validation, and announce target 404.
- Chat relay with C#-compatible 2 msg/s burst 6 token bucket.
- Chat word filter ported from `BasisWordFilter` (homoglyph table, 4,948 trigrams, 53 default words),
  with custom `config/chat_word_filter.txt` / `Configuration/chat_word_filter.txt` loading. The port
  passes the C# test corpus for punctuation, insertion, homoglyph, phrase, embedded-word and
  idempotence cases.
- Chat-typing relay with 2 event/s burst 8 and ReliableSequenced delivery.
- Jiggle-grab Start/Stop/Deny relay with 8 event/s burst 16 and 64 m Start relevance filtering.
- Camera shutter/countdown relay (event types 0/1) on ReliableSequenced.
- Voice-record request/consent relay (event types 8/9) to the target peer.
- Player temp-block notification relay (event type 2).
- Client error reports (event type 7) decoded, per-user deduplicated (256 entries), appended to
  `CrashReports/<uuid>.jsonl`, with JSON escaping and dedup cleanup on departure;
  `GlobalGetCrashReportState` is sent on join and the admin-only `SetGlobalCrashReporting`
  toggle is accepted from `admins.xml` members.
- Avatar interval byte and send throttle computed from distance with C# `EncodeAvatarIntervalByte`
  (base 50 ms, multiplier, increase rate), quality-change bypass, and full-quality broadcast bypass.
- Zstd dictionary codec (embedded C# dictionary, magicless frames, generation 1) for keyframe
  bundles; delta-only bundles stay on LZ4.
- LZ4 block codec, avatar-bundle framing/decoding (multi-message groups, codec/dictionary flags),
  a per-recipient bundle queue drained on a 12 ms tick with raw-size chunking, and channel-52
  avatar relay by default, with C#-compatible minimum message/byte thresholds that fall back to
  direct per-message sends; delta frames use the column-transposed group layout.
- Permission string codec (`PermissionCompression`: raw/Deflate, NUL-joined, 1 MB cap).
- Permission bitset codec (`PermissionBitsetMap`: 28 fixed nodes, wildcard, deny clearing, extras).
- `permissions.xml` load, parent inheritance, deny-wins resolution, default/moderator/admin seeds,
  and per-peer bitset/extras in `ServerMetaDataMessage`.
- Global lock state payload on join and admin toggles; text-chat/voice locks enforce bypass nodes;
  direct-connect lock rejects non-admin P2P requests; camera metadata policy mask is admin-settable.
- Content-load and ownership permissions enforced, including prop/world lock bypass nodes.
- Admin Ban / Kick / Unban, IP ban/unban, direct Message and MessageAll, with banned-UUID/IP auth rejection
  and `banned_players.xml` persistence; independent voice/text mutes persisted to
  `muted_players.xml` and pushed to the target on join/change; TeleportAll / TeleportPlayer;
  permission queries (node/group) answered to any player; log bundle download (Begin/Chunk/End)
  and log/crash deletion;
  Announce/Shout mode state, announce-voice relay, `GetPermissions` snapshots, and permission
  edit commands persisted to `permissions.xml`, with immediate metadata refresh for affected peers;
  server name/MOTD and peer-limit admin commands persisted to `config.xml`; restriction mode and
  file-backed allowlist enforced on auth; default-library add/remove with per-item XML files;
  rename, force-avatar, and locomotion override relays; Opus packet-loss, frame-duration,
  and per-user/global bitrate state; headless audio/disallow state with auth enforcement;
  microphone/hearing range limits, avatar scale limits, content-sphere resource limits, and
  global locomotion policy, reduction/bundle settings, image bandwidth state, and
  audio/scale/resource-limit/reduction/image-bandwidth/locomotion persistence to `config.xml`,
  with C# defaults loaded at startup (25 m audio, 0.1–100 m eye height, 32 spheres, 1/2.5/4 m/s,
  200/200/150 image bandwidth).
- Voice relay, avatar relay, scene/ownership/resource caches, default library, initial world.
- Distance reduction VeryLow/Low/Medium with C# repacker oracle test.
- C#-shaped event logs (startup/connect/disconnect/rejection/bind-failure), including the
  `Unknown EventsChannel event type` line for unrouted event types. Periodic telemetry is
  Rust-native and intentionally outside the C# projection.

## Test results

```text
cargo test: 100 passed
clippy: clean
run-compat: all PASS
check-log-compat: PASS
run-headless-56: PASS
```

## Real Unity project checks

Official boot scene `Packages/com.basis.framework/Scenes/initialization.unity`:

```text
BasisNetworkPlayers.Players        = 2
BasisNetworkPlayers.RemotePlayers  = 1
BasisNetworkPlayers.JoiningPlayers = 0
BasisLocalPlayer.PlayerReady       = True
```

| Check | Evidence |
|---|---|
| World load | active scene `test` |
| Remote spawn | `RemotePlayers = 1` |
| Remote movement | Unity `(0.81, 5.49, -17.11)` vs server `(-0.101, 5.0800004, -18.227001)` |
| Chat editor → console | `[CHAT] sender=0 text=editor-chat` |
| Chat console → editor | `[CHAT-IN] 2:headless-chat-0-21035` |
| Voice receive | `BasisNetworkHandleVoice.Message.Count = 1` |
| Departure | `Peer removed: 1`, `Player 1 removed and cleaned up.`, Unity `RemotePlayers=0` |

All Unity checks were driven through Unity MCP without window activation or mouse input.

## Transport / compute notes

- P2P NAT traversal itself runs in the client transport; the server implements the signalling
  broker, session offload, and direct-connect lock.
- GPU offload is an optional C# acceleration path; the Rust server provides the same observable
  distance/reduction behavior on the CPU.

## Last verification

```text
run-compat:        8 PASS
check-log-compat:  3 PASS
diff-log-compat:   30 normalized shared records match
cargo test:        100 passed
release build:     success
headless-56:       PASS
```



















































