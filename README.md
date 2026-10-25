# Basis Server (Rust) — compatibility workspace

This tree is a Rust implementation of the Basis Server data plane, split into Cargo crates by
module. The compatibility harness drives it with the existing C# client stack.

## Verified behavior

- LiteNetLib connection request/accept, connection-number validation, reliable-ordered,
  sequenced, unreliable, merged and compact-merged packets, cumulative acknowledgements,
  ping/pong, and outbound fragmentation.
- Protocol version 56, including the X25519 connection key, `BasisDidLoginTranscript` signature,
  ChaCha20-Poly1305 client-to-server sealing, company/product validation, password validation,
  DID challenge/response authentication (did:key Ed25519), and the server metadata message.
- Remote-player spawn batches, chat relay, voice relay, avatar keyframe relay, delta-avatar
  relay including additional-data sections, and avatar-change relay.
- A distance-based keyframe repacker that produces VeryLow/Low/Medium from the client's High
  payload. The Rust output is bit-for-bit identical to the C# `AvatarQualityRepacker` on the
  oracle vector, and a real C# client decodes all three tiers.
- Large join fills use the C# raw-Deflate `ServerReadyBatchMessage` framing when it saves space.
- Late joiners receive the most recent stored keyframe rather than the original connect-time
  pose.
- C# default `config.xml` creation on first boot (`<exe>/config/config.xml`, schema v15),
  schema upgrade of older files with the C# "adding missing settings" log, and the headless
  "NO ADMIN CONFIGURED" warning block.
- C# `config.xml` fields for port, peer limit, password/auth flags, company/product, server UUID,
  server name/MOTD, file logging, statistics, health, logging of handshakes, and quality
  distances. Unknown fields are ignored, so one config file can drive either server.
- Reliable departure broadcasts on `DisconnectionChannel` so clients despawn leavers.
- Player cleanup (`Player N removed and cleaned up.`) and empty-server NetworkID database reset lines.
- NetID assignment (channel 22), mute/typing/talk-mode event relay (channel 38), scene-data relay (channel 24), and per-sender AudioRecipients targeting.
- Jiggle-grab Start/Stop/Deny relay (event type 10) with an 8/s burst-16 token bucket and 64 m Start relevance filtering.
- Camera shutter and countdown relay (event types 0/1) on ReliableSequenced.
- Voice-record request/consent relay (event types 8/9) to the single target peer.
- Player temp-block notification relay (event type 2) to the target peer.
- Client error reports (event type 7): PermissionCompression decode, FNV dedup,
  `CrashReports/<uuid>.jsonl`, `GlobalGetCrashReportState` on join, and the admin
  `SetGlobalCrashReporting` toggle restricted to `admins.xml` when file support is on.
- `BasisFirstAdmin` headless admin seeding and the C# first-boot interactive settings/admin wizard
  (scripted end-to-end tests cover both paths).
- C# `Rejected for reason: Invalid client data.` for malformed connection payloads.
- C# `DisallowHeadless` policy rejection (`Headless client disallowed by server.`).
- C# structured server-full (kind 2) and version-mismatch (kind 1) reject payloads, plus the
  C# company/product rejection reason.
- Population-scaled authentication timeout (+12 ms/peer, capped at +45 s), matching C#.
- Password failure, authentication failure, and bind failure are reported before/without
  admission, using the C# disconnect packet layout.
- C#-shaped log records and files:
  - console and file line: `[HH:mm] [INFO|WARNING|ERROR] message`
  - file: `<exe>/Logs/yyyy-MM-dd.log` (UTC date, local-time minute)
  - 
o logs will be saved` / `Logs are saved to <absolute path>`
  - control-character sanitisation matching `BasisServerSideLogging`
  - `Peer connected: N`, `Peer removed: N`, handshake lines gated by
    `LogConnectionHandshake`, password/DID rejection messages.
- Server-info UDP query (unconnected) with the C# magic/nonce/online/max/name/MOTD response,
  per-IP 500 ms throttling, and the C# 100/s (burst 200) global token bucket.
- JSON health endpoint with the C# field set, `Cache-Control` / `X-Content-Type-Options` headers,
  GET-only 200/404/405 semantics, and the C# 32-concurrent-request 503 cap (`visitors`, `capacity`, byte/packet counters,
  drop counters, queue bounds, timestamps, version, GC-shaped block).

## Feature coverage

- Reduction scheduling: distance-based quality tiers, interval advertisement and send throttle,
  near-side repacking, keyframe/delta handling, LZ4 and dictionary-Zstd bundle compression.
- Moderation and permission enforcement with the C# rate limits, P2P signalling broker and
  direct-connect lock, chat fan-out token bucket (2 messages/s, 6 burst), and chat-typing events
  (2/s, 8 burst, ReliableSequenced). P2P NAT traversal itself is client transport; GPU offload is
  an optional C# acceleration path with equivalent CPU behavior here.
- `permissions.xml` groups/users with parent inheritance, deny-wins resolution, C# default
  `default`/`moderator`/`admin` groups, and per-peer permission bitset/extras in server metadata.
  An existing `permissions.xml` is merged with those built-in groups at boot (C#
  `EnsureDefaults`), so a file that only names an admin user still gives that account `*`
  and gives everyone else the default resource-load nodes. Admin seeding writes the complete
  group set plus `<SeededDefaults>`. Admin rights are enforced from `permissions.xml` next to
  `config.xml`; `admins.xml` is the legacy DID list that only feeds the startup `Loaded Admins`
  line.
- Global lock state (`GlobalGetLockState`) with admin toggles for content/chat/voice features;
  text-chat and voice locks enforce `basis.chat.lockbypass` / `basis.voice.lockbypass`; the
  direct-connect lock rejects non-admin P2P requests; camera metadata policy mask is admin-settable.
- Content load and ownership operations enforce `basis.resource.load.*`, `basis.resource.unload.*`,
  `basis.ownership.*`, and their global lock bypass nodes.
- Admin moderation: Ban / Kick / Unban, IP ban/unban, direct Message and MessageAll, with
  `basis.moderation.*` permission checks, banned-UUID and banned-IP auth rejection,
  `banned_players.xml` persistence, independent voice/text mutes (`muted_players.xml`), and
  join-time mute state delivery, TeleportAll / TeleportPlayer, permission queries, log bundle
  download/deletion, and Announce/Shout mode
  state broadcast with announce-voice relay, `GetPermissions` snapshots, and permission
  edit commands (user/group membership, nodes, group parents) persisted to `permissions.xml`,
  with immediate metadata refresh for affected connected peers; server name/MOTD and peer-limit
  admin commands persisted to `config.xml`; restriction mode and `BasisAllowList.txt` allowlist
  enforcement on auth; default-library add/remove with per-item XML files; rename,
  force-avatar, and locomotion override relays; Opus packet-loss / frame-duration /
  per-user and global bitrate state; headless audio/disallow state with auth enforcement;
  microphone/hearing range limits, avatar scale limits, content-sphere resource limits, and
  global locomotion policy, reduction/bundle settings, image bandwidth state, and
  audio/scale/resource-limit/reduction/image-bandwidth/locomotion persistence to `config.xml`,
  with C# defaults loaded at startup (25 m audio, 0.1–100 m eye height, 32 spheres, 1/2.5/4 m/s,
  200/200/150 image bandwidth).
- Avatar interval byte and send throttle computed from distance with C# `EncodeAvatarIntervalByte`
  (base 50 ms, multiplier, increase rate), quality-change bypass, and per-player full-quality
  broadcast bypass.
- Zstd dictionary codec (embedded C# dictionary, magicless frames, generation 1) for keyframe
  bundles; delta-only bundles stay on LZ4.
- LZ4 block codec (literal encoder + full block decoder) and avatar-bundle framing
  (`[flags][rawLen][body]`, multi-message channel groups, codec/dictionary flags) plus a
  per-recipient bundle queue drained on a 12 ms tick with raw-size chunking; the avatar relay uses
  channel 52 by default (`EnableAvatarBundleCompression`), with C#-compatible minimum
  message/byte thresholds that fall back to direct per-message sends; delta frames use the
  column-transposed group layout.
- Chat word filtering ported from `BasisWordFilter` (homoglyph table, 4,948 trigrams, default
  53-word list); active when `HasFileSupport` is enabled, as in the C# server. A custom
  `config/chat_word_filter.txt` or `Configuration/chat_word_filter.txt` is loaded when present.
- CPU/POP/BSR detail values: the Rust server emits the same record shapes from its own
  single-threaded reduction model, and the differential projection normalizes the details.
- The C# reduction system's periodic cadence: `[CPU/POP]` is emitted every 30 s from
  the Rust server, and the idle `[BSR] Load` lines when the last authenticated peer leaves.
- The full `basisctl` command set (status, players, help, shutdown, and `attach` log streaming are implemented) and
  attached-console log streaming.
- The full LiteNetLib retransmission window and backoff. A basic 100 ms / five-attempt
  resend queue is implemented, but not the complete LiteNetLib window and congestion behavior.

## Workspace layout

```text
rust-basis-server/
  Cargo.toml                 workspace
  crates/
    basis-wire/              NetDataReader/NetDataWriter primitives, localized unsafe fast path
basis-crypto/            protocol-56 X25519, HKDF, login transcript and packet AEAD
    basis-protocol/          channels, ReadyMessage, metadata, chat, voice, avatar framing
    basis-avatar/            High-to-Medium/Low/VeryLow repacker and position decode
    basis-config/            C#-compatible config.xml + environment loading
    basis-logging/           C#-shaped console/file logger
    basis-health/            HTTP health endpoint and shared counters
    basis-control/           C# basisctl Unix-domain control socket
    basis-p2p/               P2P signalling relay and offloaded-pair state
    basis-telemetry/         C#-shaped CPU/POP/BSR startup diagnostics
    basis-permissions/       permissions.xml admin seeding
    basis-setup/             first-boot interactive setup wizard
    basis-transport/         LiteNetLib-compatible UDP transport and server state
  bin/basis-server/          CLI entry point (`basis-server-rs`)
  scripts/
    run-compat.ps1           behavior harness
    check-log-compat.ps1     log-format/event harness
```

## Build and run

```powershell
cargo build --release --manifest-path rust-basis-server\Cargo.toml -p basis-server
.\rust-basis-server\target\release\basis-server-rs.exe --port=4296
```

Options:

```text
--port=4296                 UDP port
--bind=0.0.0.0              bind address
--password=...              password checked when auth is enabled
--no-auth                   disable the password check
--no-auth-identity          skip the DID challenge (development only)
--health-host=localhost     health bind host
--health-port=10666         health TCP port; 0 disables it
--health-path=/health       health request path
--config=config/config.xml  config.xml to load
--no-file-support           disable Logs/ file output
--log-dir=Logs              override the log directory
--no-avatar-reduction       relay High keyframes to every peer
```

The defaults mirror the C# server where this implementation consumes the field: password auth
and DID auth enabled, peer limit 65535, file logging enabled, health on `localhost:10666`, and
quality distances 10/20/40 m.

## Headless protocol-56 smoke test

Two protocol-56 `BasisNetworkClientConsole` instances connect without a GUI. The server relays
avatar frames and voice; the console reports:

```text
[Fairness] 2 senders seen | min=17 p1=17 median=17 p99=17 max=17
[VOICE] delivered 100.00% | received=488 lost=0 reordered=486 streams=2
[CHAT] sender=2 text=headless-chat-0-3014
[SCENE] sender=0 index=100 len=21
[OWNER] owner=1 id=headless-prop-1
[RESOURCE] id=headless-res-0 mode=0
```

The scene line is from a late joiner: it received the scene state cached from the client that
joined earlier.

The same headless process can be killed after connecting; within the 5s LiteNetLib-style liveness
window the server emits:

```text
Peer removed: 0
broadcast departure 0 to 1 peer(s)
Player 0 removed and cleaned up.
```

The surviving 56 client logs the departure too:

```text
[DEPARTURE] id=0
```

The Unity project can also be driven through Unity MCP's `Unity_RunCommand`. The official boot scene (`Packages/com.basis.framework/Scenes/initialization.unity`) connects as `EditorSmoke`, loads the server-provided `test` world, receives the remote peer (`BasisNetworkPlayers.Players = 2`, `RemotePlayers = 1`, `PlayerReady = True`), and tracks its movement (remote position `(0.81, 5.49, -17.11)` against the server's `(-0.101, 5.0800004, -18.227001)`). Editor-originated chat reaches the 56 console as `[CHAT] sender=0 text=editor-chat`. Stopping that peer produced `Peer removed: 1` / `Player 1 removed and cleaned up.` on the server and dropped Unity's `RemotePlayers` to zero. Console-originated chat was received by the Unity project as `[CHAT-IN] 2:headless-chat-0-21035` (and `[CHAT-RX] arrived bytes=25 disabled=False`). Voice receive was confirmed by forcing the voice harness to address the editor's player id: `BasisNetworkHandleVoice.Message.Count = 1` with `RemotePlayers = 1`. No window activation or mouse input is used.

`scripts/run-headless-56.ps1` runs the protocol-56 console headlessly and asserts chat, scene,
ownership, and resource traffic; it is the native-56 smoke suite.

`/api/players` returns the C#-shaped `{"players":[...]}` array from live peers, with the platform parsed from each client's metadata and the position updated from live avatar frames, and `/api/worlds` supports GET list, POST load (`{"url":"...","password":"...","persistent":false,"strategy":"immediate"}`), and DELETE unload/clear; loaded worlds are broadcast to connected clients as mode-1 resources. `defaultlibrary/*.xml` entries are sent to every client on `ServerLibraryChannel` as the C# server does. `--initial-world=<url>#<password>` seeds a mode-1 world at boot; every joining client receives it through the normal LoadResource replay. `/api/worlds/switch` loads a new world, announces it, and unloads the previous world (optionally after `delay` seconds). Synchronized loads track `PreloadReadyChannel` and broadcast `SpawnPreloadedChannel` when every peer is ready (or after the 5-minute timeout). Predownload loads only broadcast the cache request; they are not registered as active worlds and never spawn. `/api/announce` broadcasts an admin message to all clients; `/api/announce/{uuid}` targets one player. `scripts/run-compat.ps1` passes against protocol 56 health output and covers server-info,
wire/behavior compatibility, late join, departure, duplicate auth, bad password, and distance
reduction. `scripts/check-log-compat.ps1` passes the C#-shaped startup/connect/disconnect/
rejection/bind-failure log checks.

## Real client smoke test

The installed `Basis Unity.exe` (protocol 56) connects from the main menu to the local server
(port 4296). The client reaches `Authentication confirmed`, `SetupLocalPlayer`, resolves
`BasisCameraDollyManager` through the server NetID assignment, and renders its avatar. A second
56 client is announced into the world. Connecting with `--connection=` skips the menu scene load,
so the menu path is the one that must be used for visual play checks.

## Verification

Behavior harness:

```powershell
powershell -ExecutionPolicy Bypass -File rust-basis-server\scripts\run-compat.ps1
```

It runs eight checks: the raw and C# LiteNetLib unconnected server-info queries, bidirectional chat/voice/avatar/spawn
(including delta and additional-data frames), late-joiner latest-keyframe spawn, departure broadcast, duplicate-auth rejection, wrong-password
rejection, and distance reduction (VeryLow 74 B / Medium 97 B / High 159 B).

Log harness:

```powershell
powershell -ExecutionPolicy Bypass -File rust-basis-server\scripts\check-log-compat.ps1
```

It asserts the exact C# record shape, startup sequence, `Peer connected`/`Peer removed`, the
single password-rejection pair, bind failure, and that no `env_logger` module prefixes leak.

Differential oracle:

```powershell
powershell -ExecutionPolicy Bypass -File rust-basis-server\scripts\diff-log-compat.ps1
```

This runs the C# server and the Rust server with the same auth settings, drives both with the
same C# client harness, normalizes timestamps, and compares the shared event projection. Current
result: **38 normalized records match**, covering boot, CPU/POP/BSR startup diagnostics,
admin/auth startup, listener lines, worker boot, default-library load, connect/disconnect,
password rejection, DID signature rejection, authentication timeout, the optional handshake
lines, and the control-socket listener. The C# health-handle error line is outside that
projection because the C# host cannot bind its health listener here.

Unit tests:

```powershell
cargo test --manifest-path rust-basis-server\Cargo.toml
```

## Safety and unsafe policy

`crates/basis-wire/src/fast.rs` contains the hot-path `unsafe` readers; each has a `# Safety`
contract, `debug_assert!` preconditions, and a test against the safe path. The Zstd codec in
`crates/basis-protocol/src/zstd_dict.rs` contains the other `unsafe` block; it bounds every
buffer, creates/frees one context per call, and has dictionary round-trip and output-bound tests.

## Remaining verification

The protocol, log, REST, auth, permission, moderation, bundle, and headless suites run locally.
Real-client Unity checks remain reproducible when the Unity MCP bridge is available; the last
recorded session covered connect, spawn, chat, voice receive, movement, and departure. Zstd
bundle interoperability is additionally checked by decoding the Rust frames with the C# codec in
the compatibility harness.





































































