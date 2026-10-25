use basis_wire::wire::{Reader, WireError, WireResult, Writer};
use ed25519_dalek::VerifyingKey;

pub const PROTOCOL_VERSION: u16 = 56;
pub const LEGACY_PROTOCOL_VERSION: u16 = 55;
pub const SERVER_INFO_QUERY_MAGIC: u32 = 0xBA51_5101;
pub const SERVER_INFO_RESPONSE_MAGIC: u32 = 0xBA51_5102;
pub const SERVER_INFO_PROTOCOL_VERSION: u16 = 1;
pub const SERVER_INFO_MIN_REQUEST_BYTES: usize = 384;
pub const SERVER_INFO_NAME_MAX: usize = 64;
pub const SERVER_INFO_MOTD_MAX: usize = 256;
pub const MAX_PEER_ID_SMALL: u16 = 255;

pub const AUTH_IDENTITY_CHANNEL: u8 = 0;
pub const METADATA_CHANNEL: u8 = 1;
pub const DISCONNECTION_CHANNEL: u8 = 2;
pub const VOICE_CHANNEL: u8 = 3;
pub const ANNOUNCE_VOICE_CHANNEL: u8 = 4;
pub const AUDIO_RECIPIENTS_CHANNEL: u8 = 5;
pub const GET_CURRENT_OWNER_CHANNEL: u8 = 19;
pub const CHANGE_CURRENT_OWNER_CHANNEL: u8 = 20;
pub const REMOVE_CURRENT_OWNER_CHANNEL: u8 = 21;
pub const AUDIO_RECIPIENTS_LARGE_CHANNEL: u8 = 39;
pub const AUDIO_RECIPIENTS_INVERTED_CHANNEL: u8 = 49;
pub const AUDIO_RECIPIENTS_INVERTED_LARGE_CHANNEL: u8 = 50;
pub const AUDIO_RECIPIENTS_BITFIELD_CHANNEL: u8 = 51;
pub const PLAYER_AVATAR_VERY_LOW_CHANNEL: u8 = 6;
pub const PLAYER_AVATAR_VERY_LOW_ADDITIONAL_CHANNEL: u8 = 7;
pub const PLAYER_AVATAR_LOW_CHANNEL: u8 = 8;
pub const PLAYER_AVATAR_LOW_ADDITIONAL_CHANNEL: u8 = 9;
pub const PLAYER_AVATAR_MEDIUM_CHANNEL: u8 = 10;
pub const PLAYER_AVATAR_MEDIUM_ADDITIONAL_CHANNEL: u8 = 11;
pub const PLAYER_AVATAR_HIGH_CHANNEL: u8 = 12;
pub const PLAYER_AVATAR_HIGH_ADDITIONAL_CHANNEL: u8 = 13;
pub const AVATAR_CHANGE_CHANNEL: u8 = 14;
pub const AVATAR_CHANGE_KIND_FULL: u8 = 0;
pub const AVATAR_CHANNEL: u8 = 15;
pub const NET_ID_ASSIGN_CHANNEL: u8 = 22;
pub const EVENTS_CHANNEL: u8 = 38;
pub const SCENE_CHANNEL: u8 = 24;
pub const ADMIN_CHANNEL: u8 = 34;
pub const SERVER_LIBRARY_CHANNEL: u8 = 53;
pub const ADMIN_MESSAGE_PLAYER: u8 = 3;
pub const ADMIN_MESSAGE_ALL: u8 = 4;
pub const LOAD_RESOURCE_CHANNEL: u8 = 25;
pub const UNLOAD_RESOURCE_CHANNEL: u8 = 26;
pub const PRELOAD_READY_CHANNEL: u8 = 27;
pub const SPAWN_PRELOADED_CHANNEL: u8 = 28;
pub const CREATE_REMOTE_PLAYER_CHANNEL: u8 = 16;
pub const CREATE_REMOTE_PLAYERS_FOR_NEW_PEER_CHANNEL: u8 = 17;
pub const CHAT_CHANNEL: u8 = 18;
pub const DELTA_AVATAR_CHANNEL: u8 = 30;
pub const LARGE_AVATAR_VERY_LOW_CHANNEL: u8 = 41;
pub const LARGE_AVATAR_LOW_CHANNEL: u8 = 43;
pub const LARGE_AVATAR_MEDIUM_CHANNEL: u8 = 45;
pub const LARGE_AVATAR_HIGH_CHANNEL: u8 = 47;
pub const LARGE_AVATAR_HIGH_ADDITIONAL_CHANNEL: u8 = 48;
pub const VOICE_LARGE_CHANNEL: u8 = 40;
pub const COMPRESSED_AVATAR_BUNDLE_CHANNEL: u8 = 52;
pub const REGISTRY_CONTROL_CHANNEL: u8 = 60;

pub const REGISTRY_SUB_SUPPLY: u8 = 0;
pub const REGISTRY_SUB_SUBSCRIBE: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AvatarQuality {
    VeryLow = 0,
    Low = 1,
    Medium = 2,
    High = 3,
}

impl AvatarQuality {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::VeryLow),
            1 => Some(Self::Low),
            2 => Some(Self::Medium),
            3 => Some(Self::High),
            _ => None,
        }
    }

    pub fn payload_size(self) -> usize {
        match self {
            Self::VeryLow => 74,
            Self::Low => 83,
            Self::Medium => 97,
            Self::High => 159,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ClientMetadata {
    pub uuid: String,
    pub display_name: String,
    pub platform: String,
}

#[derive(Debug, Clone)]
pub struct ReadyInfo {
    pub metadata: ClientMetadata,
    pub metadata_raw: Vec<u8>,
    pub ready_raw: Vec<u8>,
    pub avatar_change_raw: Vec<u8>,
    pub avatar_sync_raw: Vec<u8>,
    pub avatar_quality: AvatarQuality,
    pub avatar_payload: Vec<u8>,
    pub avatar_additional: Vec<u8>,
    pub avatar_change_len: usize,
}

#[derive(Debug, Clone)]
pub struct ConnectionData {
    pub version: u16,
    pub company_name: String,
    pub product_name: String,
    pub auth: Vec<u8>,
    pub client_public: Option<[u8; 32]>,
    pub payload_hash: [u8; 32],
    pub ready: ReadyInfo,
}

pub fn parse_connection_data(data: &[u8]) -> WireResult<ConnectionData> {
    let mut r = Reader::new(data);
    let version = r.get_u16()?;
    let tag = r.get_u8()?;
    let (company_name, product_name) = match tag {
        0 => (r.get_string()?, r.get_string()?),
        1 => ("Basis Unity".to_string(), "Basis Unity".to_string()),
        other => return Err(WireError(format!("unknown company tag {other}"))),
    };
    let auth = r.get_bytes_with_length()?.to_vec();
    let payload_start = r.position();
    let client_public = if version >= 56 {
        let key = r.get_bytes_with_length()?;
        if key.len() != 32 {
            return Err(WireError(format!(
                "invalid client connection key length {}",
                key.len()
            )));
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(key);
        Some(key_bytes)
    } else {
        None
    };
    let payload_hash = basis_crypto::hash_connection_payload(&data[payload_start..]);
    let ready = parse_ready(&mut r)?;
    Ok(ConnectionData {
        version,
        company_name,
        product_name,
        auth,
        client_public,
        payload_hash,
        ready,
    })
}

fn parse_ready(r: &mut Reader<'_>) -> WireResult<ReadyInfo> {
    let metadata_start = r.position();
    let (metadata, metadata_end) = parse_client_metadata(r)?;
    let metadata_raw = r.raw()[metadata_start..metadata_end].to_vec();

    // ClientAvatarChangeMessage
    let avatar_change_start = r.position();
    let load_mode = r.get_u8()?;
    let avatar_len = r.get_u16()? as usize;
    let _avatar_bytes = r.get_bytes(avatar_len)?;
    let _local_avatar_index = r.get_u8()?;
    let _arm = r.get_u16()?;
    let _leg = r.get_u16()?;
    let _torso = r.get_u16()?;
    let _ = load_mode;
    let avatar_change_end = r.position();
    let avatar_change_raw = r.raw()[avatar_change_start..avatar_change_end].to_vec();
    let avatar_change_len = avatar_change_end - metadata_end;

    // LocalAvatarSyncMessage (initial connection form, quality in payload)
    let avatar_sync_start = r.position();
    let q = r.get_u8()?;
    let quality = AvatarQuality::from_u8(q)
        .ok_or_else(|| WireError(format!("invalid avatar quality {q}")))?;
    let payload = r.get_bytes(quality.payload_size())?.to_vec();
    let additional_size = r.get_u8()? as usize;
    let mut additional = Vec::new();
    if additional_size > 0 {
        let _linked = r.get_u8()?;
        for _ in 0..additional_size {
            let size = r.get_u8()? as usize;
            let _index = r.get_u8()?;
            let start = r.position();
            let _ = r.get_bytes(size)?;
            additional.extend_from_slice(&r.raw()[start..start + size]);
        }
    }

    let ready_end = r.position();
    let avatar_sync_raw = r.raw()[avatar_sync_start..ready_end].to_vec();
    Ok(ReadyInfo {
        metadata,
        metadata_raw,
        ready_raw: r.raw()[metadata_start..ready_end].to_vec(),
        avatar_change_raw,
        avatar_sync_raw,
        avatar_quality: quality,
        avatar_payload: payload,
        avatar_additional: additional,
        avatar_change_len,
    })
}

pub fn parse_client_metadata_bytes(data: &[u8]) -> WireResult<ClientMetadata> {
    let mut r = Reader::new(data);
    let (metadata, _) = parse_client_metadata(&mut r)?;
    Ok(metadata)
}

fn parse_client_metadata(r: &mut Reader<'_>) -> WireResult<(ClientMetadata, usize)> {
    let uuid = read_compact_id(r)?;
    let display_name = r.get_string()?;
    let platform = read_platform(r)?;
    Ok((
        ClientMetadata {
            uuid,
            display_name,
            platform,
        },
        r.position(),
    ))
}

pub fn read_compact_id(r: &mut Reader<'_>) -> WireResult<String> {
    let tag = r.get_u8()?;
    match tag {
        0 => r.get_string(),
        1 => {
            let format = r.get_u8()?;
            let raw = r.get_bytes(16)?;
            Ok(render_uuid(raw, format))
        }
        2 => Ok(r.get_u64()?.to_string()),
        3 => {
            let flags = r.get_u8()?;
            let len = r.get_u8()? as usize;
            let bytes = r.get_bytes(len)?;
            let mut s = String::with_capacity(len * 2);
            for b in bytes {
                if flags & 1 != 0 {
                    s.push_str(&format!("{b:02X}"));
                } else {
                    s.push_str(&format!("{b:02x}"));
                }
            }
            Ok(s)
        }
        4 => {
            let len = r.get_u8()? as usize;
            let body = r.get_bytes(len)?;
            Ok(format!("did:key:{}", String::from_utf8_lossy(body)))
        }
        other => Err(WireError(format!("unknown compact id tag {other}"))),
    }
}

fn render_uuid(bytes: &[u8], format: u8) -> String {
    if bytes.len() != 16 {
        return String::new();
    }
    let mut b = [0u8; 16];
    b.copy_from_slice(bytes);
    // .NET Guid.ToByteArray() stores the first three fields little-endian.
    let d1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let d2 = u16::from_le_bytes([b[4], b[5]]);
    let d3 = u16::from_le_bytes([b[6], b[7]]);
    let dashed = format!(
        "{d1:08x}-{d2:04x}-{d3:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
    );
    match format {
        1 => dashed.to_uppercase(),
        2 => dashed.replace('-', ""),
        3 => dashed.replace('-', "").to_uppercase(),
        _ => dashed,
    }
}

pub fn write_compact_id(w: &mut Writer, value: &str) {
    if let Some(body) = value.strip_prefix("did:key:") {
        if !body.is_empty() && body.len() <= 255 {
            w.put_u8(4);
            w.put_u8(body.len() as u8);
            w.put_bytes(body.as_bytes());
            return;
        }
    }
    w.put_u8(0);
    w.put_string(value);
}

pub fn read_platform(r: &mut Reader<'_>) -> WireResult<String> {
    let id = r.get_u8()?;
    if id == 0 {
        return r.get_string();
    }
    let known = KNOWN_PLATFORMS.get((id - 1) as usize);
    Ok(known.copied().unwrap_or("").to_string())
}

const KNOWN_PLATFORMS: &[&str] = &[
    "WindowsPlayer",
    "WindowsEditor",
    "WindowsServer",
    "OSXPlayer",
    "OSXEditor",
    "OSXServer",
    "LinuxPlayer",
    "LinuxEditor",
    "LinuxServer",
    "Android",
    "IPhonePlayer",
    "VisionOS",
    "WebGLPlayer",
    "PS4",
    "PS5",
    "XboxOne",
    "GameCoreXboxOne",
    "GameCoreXboxSeries",
    "Switch",
    "tvOS",
    "WSAPlayerX86",
    "WSAPlayerX64",
    "WSAPlayerARM",
    "EmbeddedLinuxArm64",
    "EmbeddedLinuxArm32",
    "EmbeddedLinuxX64",
    "EmbeddedLinuxX86",
    "QNXArm32",
    "QNXArm64",
    "QNXX64",
    "QNXX86",
    "Stadia",
    "CloudRendering",
    "LinuxHeadlessSimulation",
    "Lumin",
    "Headless",
];

pub fn did_to_verifying_key(did: &str) -> Result<VerifyingKey, String> {
    let body = did
        .strip_prefix("did:key:")
        .ok_or_else(|| format!("not a did:key: {did}"))?;
    let body = body
        .strip_prefix('z')
        .ok_or_else(|| "did:key is not base58btc (missing z)".to_string())?;
    let decoded = bs58::decode(body)
        .into_vec()
        .map_err(|e| format!("base58 decode failed: {e}"))?;
    // did:key ed25519 multicodec is 0xed 0x01.
    if decoded.len() != 34 || decoded[0] != 0xed || decoded[1] != 0x01 {
        return Err(format!(
            "unsupported did:key multicodec (len={})",
            decoded.len()
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded[2..]);
    VerifyingKey::from_bytes(&key).map_err(|e| format!("invalid ed25519 key: {e}"))
}

pub fn build_challenge_v2(nonce: &[u8], server_public: &[u8; 32], server_uuid: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_bytes_with_length(nonce);
    w.put_bytes_with_length(server_public);
    w.put_bytes_with_length(server_uuid.as_bytes());
    w.into_vec()
}

pub fn build_challenge(nonce: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_u16(nonce.len() as u16);
    w.put_bytes(nonce);
    w.into_vec()
}

pub fn parse_auth_response(data: &[u8]) -> WireResult<(Vec<u8>, String)> {
    let mut r = Reader::new(data);
    let sig = r.get_bytes_with_length()?.to_vec();
    let frag = r.get_bytes_with_length()?;
    let frag = String::from_utf8_lossy(frag).into_owned();
    Ok((sig, frag))
}

pub fn build_server_metadata(metadata_raw: &[u8], server_uuid: &str, peer_limit: u16) -> Vec<u8> {
    build_server_metadata_with_permissions(metadata_raw, server_uuid, peer_limit, &[], &[])
}

pub fn build_server_metadata_with_permissions(
    metadata_raw: &[u8],
    server_uuid: &str,
    peer_limit: u16,
    permissions_bitset: &[u8],
    extra_permissions: &[String],
) -> Vec<u8> {
    let mut w = Writer::with_capacity(metadata_raw.len() + 96);
    w.put_bytes(metadata_raw);
    w.put_i32(50); // SyncInterval
    w.put_i32(1); // BaseMultiplier
    w.put_f32(0.005); // IncreaseRate
    w.put_f32(2.55); // SlowestSendRate
    w.put_i32(peer_limit as i32); // PeerLimit
    w.put_bytes_with_length(permissions_bitset);
    w.put_u16(extra_permissions.len() as u16);
    if !extra_permissions.is_empty() {
        let compressed = crate::permission_compression::compress(extra_permissions);
        w.put_bytes_with_length(&compressed);
    }
    w.put_bool(true); // UplinkDeltaEnabled
    w.put_i32(200); // ImageShareEgressMegabitsPerSecond
    w.put_f32(64.0); // ImagePickupRangeMeters
    write_compact_id(&mut w, server_uuid);
    w.into_vec()
}

pub fn build_registry_supply() -> Vec<u8> {
    let mut w = Writer::new();
    w.put_u8(REGISTRY_SUB_SUPPLY);
    // A minimal but valid manifest: core ids with their dedicated channels.
    // The client resolves handlers by channel, so an empty supply is also tolerated.
    w.put_u16(0);
    w.into_vec()
}

pub fn build_ready_batch(records: &[(u16, Vec<u8>)]) -> Vec<u8> {
    use flate2::write::DeflateEncoder;
    use flate2::Compression;
    use std::io::Write;

    let mut payload = Writer::new();
    for (id, ready) in records {
        payload.put_u16(*id);
        payload.put_bytes(ready);
    }
    let payload = payload.into_vec();
    let mut framed = payload;
    let mut compressed = false;
    if framed.len() >= 256 {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        if encoder.write_all(&framed).is_ok() {
            if let Ok(candidate) = encoder.finish() {
                if candidate.len() < framed.len() {
                    framed = candidate;
                    compressed = true;
                }
            }
        }
    }
    let mut w = Writer::new();
    w.put_u16(records.len() as u16);
    w.put_bool(compressed);
    w.put_i32(framed.len() as i32);
    w.put_bytes(&framed);
    w.into_vec()
}

pub fn build_server_ready(id: u16, ready: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_u16(id);
    w.put_bytes(ready);
    w.into_vec()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvatarData {
    pub player_id: u16,
    pub avatar_link_index: u8,
    pub message_index: u8,
    pub recipients: Vec<u16>,
    pub payload: Vec<u8>,
}

pub fn parse_avatar_data(data: &[u8]) -> WireResult<AvatarData> {
    let mut r = Reader::new(data);
    let player_id = r.get_u16()?;
    let avatar_link_index = r.get_u8()?;
    let message_index = r.get_u8()?;
    let recipient_count = r.get_u16()? as usize;
    if recipient_count > r.remaining() / 2 {
        return Err(WireError("avatar recipient count exceeds payload".into()));
    }
    let mut recipients = Vec::with_capacity(recipient_count);
    for _ in 0..recipient_count {
        recipients.push(r.get_u16()?);
    }
    let payload = r.get_bytes(r.remaining())?.to_vec();
    Ok(AvatarData {
        player_id,
        avatar_link_index,
        message_index,
        recipients,
        payload,
    })
}

pub fn build_server_avatar_data(sender: u16, data: &AvatarData) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_u16(sender);
    w.put_u16(data.player_id);
    w.put_u8(data.avatar_link_index);
    w.put_u8(data.message_index);
    w.put_bytes(&data.payload);
    w.into_vec()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SceneData {
    pub message_index: u16,
    pub recipients: Vec<u16>,
    pub payload: Vec<u8>,
}

pub fn parse_ownership(data: &[u8]) -> WireResult<(u16, String)> {
    let mut r = Reader::new(data);
    let owner = r.get_u16()?;
    let id = r.get_string()?;
    Ok((owner, id))
}

pub fn build_ownership(owner: u16, id: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_u16(owner);
    w.put_string(id);
    w.into_vec()
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResourceSummary {
    pub mode: u8,
    pub id: String,
    pub url: String,
    pub persistent: bool,
    pub admin_locked: bool,
    pub strategy: u8,
}

pub struct WorldResource {
    pub net_id: String,
    pub url: String,
    pub password: String,
    pub persistent: bool,
    pub strategy: u8,
}

pub fn build_load_resource(world: &WorldResource) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_u8(1);
    w.put_string(&world.net_id);
    w.put_string(&world.password);
    w.put_string(&world.url);
    w.put_string("server");
    w.put_bool(false);
    w.put_bool(world.persistent);
    w.put_bool(false);
    w.put_bool(false);
    w.put_bool(false);
    w.put_u8(world.strategy);
    w.into_vec()
}

pub fn parse_preload_ready(data: &[u8]) -> WireResult<(String, bool)> {
    let mut r = Reader::new(data);
    let net_id = r.get_string()?;
    let ready = r.get_bool()?;
    Ok((net_id, ready))
}

pub fn build_spawn_preloaded(net_id: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_string(net_id);
    w.into_vec()
}

pub fn build_unload_resource(net_id: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_u8(1);
    w.put_string(net_id);
    w.into_vec()
}

pub fn parse_resource_summary(data: &[u8]) -> WireResult<ResourceSummary> {
    let mut r = Reader::new(data);
    let mode = r.get_u8()?;
    let id = r.get_string()?;
    let _password = r.get_string()?;
    let url = r.get_string()?;
    let _creator = r.get_string()?;
    let admin_locked = r.get_bool()?;
    let persistent = r.get_bool()?;
    let _static = r.get_bool()?;
    let _static_admin = r.get_bool()?;
    let _modify_scale = r.get_bool()?;
    let strategy = r.get_u8()?;
    if mode == 0 {
        for _ in 0..10 {
            let _ = r.get_f32()?;
        }
    }
    Ok(ResourceSummary {
        mode,
        id,
        url,
        persistent,
        admin_locked,
        strategy,
    })
}

pub fn parse_resource_id(data: &[u8]) -> WireResult<(u8, String)> {
    let mut r = Reader::new(data);
    let mode = r.get_u8()?;
    let id = r.get_string()?;
    Ok((mode, id))
}

pub fn parse_unload_resource_id(data: &[u8]) -> WireResult<String> {
    let mut r = Reader::new(data);
    let _mode = r.get_u8()?;
    r.get_string()
}

pub fn parse_scene_data(data: &[u8]) -> WireResult<SceneData> {
    let mut r = Reader::new(data);
    let message_index = r.get_u16()?;
    let recipient_count = r.get_u16()? as usize;
    if recipient_count > r.remaining() / 2 {
        return Err(WireError("scene recipient count exceeds payload".into()));
    }
    let mut recipients = Vec::with_capacity(recipient_count);
    for _ in 0..recipient_count {
        recipients.push(r.get_u16()?);
    }
    let payload = r.get_bytes(r.remaining())?.to_vec();
    Ok(SceneData {
        message_index,
        recipients,
        payload,
    })
}

pub fn build_server_scene_data(sender: u16, data: &SceneData) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_u16(sender);
    w.put_u16(data.message_index);
    w.put_bytes(&data.payload);
    w.into_vec()
}

pub fn parse_net_id(data: &[u8]) -> WireResult<String> {
    let mut r = Reader::new(data);
    r.get_string()
}

pub fn build_net_id(id: &str, value: u16) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_string(id);
    w.put_u16(value);
    w.into_vec()
}

pub fn parse_chat(data: &[u8]) -> WireResult<(String, bool)> {
    let mut r = Reader::new(data);
    let len = r.get_u16()? as usize;
    let bytes = r.get_bytes(len.min(512))?;
    let sound = if r.remaining() > 0 {
        r.get_bool()?
    } else {
        true
    };
    // Skip any excess the sender declared beyond the hard cap.
    if len > 512 && r.remaining() >= len - 512 {
        let _ = r.get_bytes(len - 512);
    }
    Ok((sanitize_chat(&String::from_utf8_lossy(bytes)), sound))
}

pub fn sanitize_chat(text: &str) -> String {
    // C# clamps to 256 UTF-16 code units, then trims scalars until the UTF-8 length fits 512.
    let mut out = String::with_capacity(text.len().min(512));
    let mut units = 0usize;
    for ch in text.chars() {
        let width = ch.len_utf16();
        if units + width > 256 {
            break;
        }
        units += width;
        out.push(ch);
    }
    while out.len() > 512 {
        if out.pop().is_none() {
            break;
        }
    }
    out
}

pub fn build_server_chat(sender: u16, text: &str, sound: bool) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_u16(sender);
    let text = sanitize_chat(text);
    let bytes = text.as_bytes();
    let len = bytes.len().min(512);
    w.put_u16(len as u16);
    w.put_bytes(&bytes[..len]);
    w.put_bool(sound);
    w.into_vec()
}

pub fn build_admin_message(mode: u8, message: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_u8(mode);
    w.put_string(&sanitize_chat(message));
    w.into_vec()
}

#[derive(Debug, Clone)]
pub struct ServerLibraryItem {
    pub mode: u8,
    pub url: String,
    pub password: String,
}

pub fn build_server_library(items: &[ServerLibraryItem]) -> Vec<u8> {
    let mut raw = Writer::new();
    raw.put_u16(items.len() as u16);
    for item in items {
        raw.put_u8(item.mode);
        raw.put_string(&item.url);
        raw.put_string(&item.password);
    }
    let raw = raw.into_vec();
    let mut wire = Writer::new();
    wire.put_u16(raw.len() as u16);
    wire.put_u16(0);
    wire.put_bytes(&raw);
    wire.into_vec()
}

pub fn parse_voice(data: &[u8]) -> WireResult<(u8, u8, Vec<u8>)> {
    let mut r = Reader::new(data);
    let seq = r.get_u8()?;
    let silence = r.get_u8()?;
    let frame = r.remaining();
    let body = r.get_bytes(frame)?.to_vec();
    Ok((seq, silence, body))
}

pub fn build_server_voice(sender: u16, seq: u8, silence: u8, frame: &[u8]) -> Vec<u8> {
    let mut w = Writer::with_capacity(frame.len() + 4);
    w.put_u16(sender);
    w.put_u8(seq);
    w.put_u8(silence);
    w.put_bytes(frame);
    w.into_vec()
}

pub fn parse_avatar_uplink(data: &[u8]) -> WireResult<(u8, AvatarQuality, Vec<u8>, Vec<u8>)> {
    let mut r = Reader::new(data);
    let seq = r.get_u8()?;
    let q = AvatarQuality::from_u8(r.get_u8()?)
        .ok_or_else(|| WireError("invalid avatar uplink quality".into()))?;
    // Uplink channel payload is quality-less, but some paths include the quality byte.
    // The caller distinguishes by channel; this helper is for the quality-in-payload form.
    let _ = q;
    let payload = r.get_bytes(r.remaining())?.to_vec();
    Ok((seq, q, payload, Vec::new()))
}

pub fn encode_avatar_interval(interval_ms: i32, base_ms: i32) -> u8 {
    let relative = interval_ms - base_ms;
    if relative <= 0 {
        return 0;
    }
    if relative < 200 {
        return relative as u8;
    }
    let steps = (relative - 200 + 6) / 12;
    (200 + steps.min(55)) as u8
}

pub fn decode_avatar_interval(encoded: u8, base_ms: i32) -> i32 {
    if encoded < 200 {
        base_ms + encoded as i32
    } else {
        base_ms + 200 + (encoded as i32 - 200) * 12
    }
}

pub fn build_avatar_relay(sender: u16, seq: u8, payload: &[u8], additional: &[u8]) -> Vec<u8> {
    build_avatar_relay_with_interval(sender, seq, payload, additional, 0)
}

pub fn build_avatar_relay_with_interval(
    sender: u16,
    seq: u8,
    payload: &[u8],
    additional: &[u8],
    interval: u8,
) -> Vec<u8> {
    let mut w = Writer::with_capacity(payload.len() + additional.len() + 4);
    // Small-id server keyframe frame: [playerId:1][interval:1][sequence:1][payload][additional?].
    w.put_u8(sender as u8);
    w.put_u8(interval);
    w.put_u8(seq);
    w.put_bytes(payload);
    if !additional.is_empty() {
        // Already framed as [count][linked][entries] or [0].
        w.put_bytes(additional);
    }
    w.into_vec()
}

/// Builds the server-to-client delta frame from a client delta uplink.
/// Uplink: [header][seq][baseSeq][body][additional?]
/// Downlink: [header][playerId:1][interval:1][seq][baseSeq][body][additional?]
pub fn build_delta_relay(sender: u16, uplink: &[u8]) -> Option<Vec<u8>> {
    if uplink.len() < 3 {
        return None;
    }
    let header = uplink[0];
    if header & 0x80 != 0 {
        return None; // control frame, not a delta
    }
    let mut w = Writer::with_capacity(uplink.len() + 2);
    w.put_u8(header & 0x0F); // preserve quality + additional, force small id
    w.put_u8(sender as u8);
    w.put_u8(0); // interval
    w.put_bytes(&uplink[1..]);
    Some(w.into_vec())
}

/// Parses a channel-based avatar uplink (channel 12/13): [seq][payload][additional?].
pub fn parse_avatar_channel_payload(
    data: &[u8],
    has_additional: bool,
) -> WireResult<(u8, Vec<u8>, Vec<u8>)> {
    let mut r = Reader::new(data);
    let seq = r.get_u8()?;
    let payload = r.get_bytes(AvatarQuality::High.payload_size())?.to_vec();
    let mut additional = Vec::new();
    if has_additional && r.remaining() > 0 {
        let count = r.get_u8()? as usize;
        if count > 0 {
            let linked = r.get_u8()?;
            let mut aw = Writer::new();
            aw.put_u8(count as u8);
            aw.put_u8(linked);
            for _ in 0..count {
                let start = r.position();
                let size = r.get_u8()? as usize;
                let _index = r.get_u8()?;
                let _ = r.get_bytes(size)?;
                aw.put_bytes(&r.raw()[start..r.position()]);
            }
            additional = aw.into_vec();
        } else {
            additional.push(0);
        }
    }
    Ok((seq, payload, additional))
}

#[cfg(test)]
mod interval_tests {
    use super::*;

    #[test]
    fn avatar_interval_round_trips_base_and_extended_ranges() {
        for encoded in [0u8, 50, 199, 200, 220, 255] {
            let milliseconds = decode_avatar_interval(encoded, 50);
            assert_eq!(encode_avatar_interval(milliseconds, 50), encoded);
        }
    }

    #[test]
    fn avatar_interval_encodes_distance_scaled_values() {
        assert_eq!(encode_avatar_interval(50, 50), 0);
        assert_eq!(encode_avatar_interval(75, 50), 25);
        assert_eq!(decode_avatar_interval(25, 50), 75);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_key_decodes_ed25519_multicodec() {
        // A syntactically valid did:key generated from 32 zero bytes (key validity is checked
        // separately; this asserts the multicodec/base58 framing).
        let raw = [0u8; 32];
        let mut bytes = vec![0xed, 0x01];
        bytes.extend_from_slice(&raw);
        let did = format!("did:key:z{}", bs58::encode(bytes).into_string());
        let key = did_to_verifying_key(&did).unwrap();
        assert_eq!(key.to_bytes(), raw);
    }

    #[test]
    fn chat_sanitizer_clamps_characters_and_bytes() {
        assert_eq!(sanitize_chat("hello"), "hello");
        let long = "a".repeat(300);
        assert_eq!(sanitize_chat(&long).len(), 256);
        let wide = "あ".repeat(300);
        assert_eq!(sanitize_chat(&wide).len(), 510);
        let emoji = "😀".repeat(200);
        let clamped = sanitize_chat(&emoji);
        assert_eq!(clamped.encode_utf16().count(), 256);
        assert!(clamped.len() <= 512);
    }

    #[test]
    fn challenge_matches_csharp_256_byte_nonce() {
        let nonce = [0xABu8; 256];
        let challenge = build_challenge(&nonce);
        assert_eq!(challenge.len(), 258);
        assert_eq!(u16::from_le_bytes([challenge[0], challenge[1]]), 256);
        assert_eq!(&challenge[2..], &nonce);
    }

    #[test]
    fn ready_batch_round_trip_shape() {
        let ready = vec![1, 2, 3, 4];
        let batch = build_ready_batch(&[(7, ready.clone())]);
        let mut r = Reader::new(&batch);
        assert_eq!(r.get_u16().unwrap(), 1);
        assert!(!r.get_bool().unwrap());
        let len = r.get_i32().unwrap() as usize;
        let body = r.get_bytes(len).unwrap();
        let mut br = Reader::new(body);
        assert_eq!(br.get_u16().unwrap(), 7);
        assert_eq!(br.get_bytes(4).unwrap(), &ready);
    }

    #[test]
    fn ready_batch_compresses_large_join_fills() {
        use flate2::read::DeflateDecoder;
        use std::io::Read;
        let ready = vec![0x41u8; 4096];
        let batch = build_ready_batch(&[(1, ready.clone()), (2, ready.clone())]);
        let mut r = Reader::new(&batch);
        assert_eq!(r.get_u16().unwrap(), 2);
        assert!(r.get_bool().unwrap());
        let len = r.get_i32().unwrap() as usize;
        let body = r.get_bytes(len).unwrap();
        let mut decoder = DeflateDecoder::new(body);
        let mut inflated = Vec::new();
        decoder.read_to_end(&mut inflated).unwrap();
        let mut br = Reader::new(&inflated);
        assert_eq!(br.get_u16().unwrap(), 1);
        assert_eq!(br.get_bytes(4096).unwrap(), ready.as_slice());
        assert_eq!(br.get_u16().unwrap(), 2);
        assert_eq!(br.get_bytes(4096).unwrap(), ready.as_slice());
    }

    #[test]
    fn resource_summary_parses_world() {
        let mut w = Writer::new();
        w.put_u8(1);
        w.put_string("world-1");
        w.put_string("");
        w.put_string("https://example.invalid/world.bee");
        w.put_string("did:key:creator");
        w.put_bool(false);
        w.put_bool(true);
        w.put_bool(false);
        w.put_bool(false);
        w.put_bool(true);
        w.put_u8(0);
        let summary = parse_resource_summary(&w.into_vec()).unwrap();
        assert_eq!(summary.mode, 1);
        assert_eq!(summary.id, "world-1");
        assert_eq!(summary.url, "https://example.invalid/world.bee");
        assert!(summary.persistent);
        assert!(!summary.admin_locked);
        assert_eq!(summary.strategy, 0);
    }

    #[test]
    fn preload_ready_round_trip() {
        let mut w = Writer::new();
        w.put_string("world-1");
        w.put_bool(true);
        let (net_id, ready) = parse_preload_ready(&w.into_vec()).unwrap();
        assert_eq!(net_id, "world-1");
        assert!(ready);
        let spawn = build_spawn_preloaded("world-1");
        let mut r = Reader::new(&spawn);
        assert_eq!(r.get_string().unwrap(), "world-1");
    }

    #[test]
    fn server_library_wire_round_trip() {
        let wire = build_server_library(&[ServerLibraryItem {
            mode: 2,
            url: "https://example.invalid/prop.bee".into(),
            password: "pw".into(),
        }]);
        let raw_len = u16::from_le_bytes([wire[0], wire[1]]) as usize;
        let compressed = u16::from_le_bytes([wire[2], wire[3]]);
        assert_eq!(compressed, 0);
        assert_eq!(wire.len(), raw_len + 4);
    }

    #[test]
    fn admin_message_has_mode_prefix() {
        let payload = build_admin_message(ADMIN_MESSAGE_ALL, "hello");
        assert_eq!(payload[0], ADMIN_MESSAGE_ALL);
    }

    #[test]
    fn built_world_resource_summarizes() {
        let payload = build_load_resource(&WorldResource {
            net_id: "world-1".into(),
            url: "https://example.invalid/world.bee".into(),
            password: String::new(),
            persistent: true,
            strategy: 0,
        });
        let summary = parse_resource_summary(&payload).unwrap();
        assert_eq!(summary.mode, 1);
        assert_eq!(summary.id, "world-1");
        assert_eq!(summary.url, "https://example.invalid/world.bee");
        assert!(summary.persistent);
        assert_eq!(
            parse_unload_resource_id(&build_unload_resource("world-1")).unwrap(),
            "world-1"
        );
    }

    #[test]
    fn resource_id_round_trip() {
        let mut message = Vec::new();
        message.push(0);
        message.extend_from_slice(&(7u16).to_le_bytes());
        message.extend_from_slice(b"prop-1");
        let (mode, object) = parse_resource_id(&message).unwrap();
        assert_eq!(mode, 0);
        assert_eq!(object, "prop-1");
        assert_eq!(parse_unload_resource_id(&message).unwrap(), "prop-1");
    }

    #[test]
    fn ownership_round_trip() {
        let message = build_ownership(7, "prop-1");
        let (owner, object) = parse_ownership(&message).unwrap();
        assert_eq!(owner, 7);
        assert_eq!(object, "prop-1");
    }

    #[test]
    fn scene_round_trip() {
        let mut data = Vec::new();
        data.extend_from_slice(&7u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(b"payload");
        let scene = parse_scene_data(&data).unwrap();
        assert_eq!(scene.message_index, 7);
        assert_eq!(scene.payload, b"payload");
        let relay = build_server_scene_data(3, &scene);
        assert_eq!(u16::from_le_bytes([relay[0], relay[1]]), 3);
        assert_eq!(u16::from_le_bytes([relay[2], relay[3]]), 7);
        assert_eq!(&relay[4..], b"payload");
    }

    #[test]
    fn net_id_round_trip() {
        let message = build_net_id("BasisImagePickup", 42);
        assert_eq!(parse_net_id(&message).unwrap(), "BasisImagePickup");
        assert_eq!(
            u16::from_le_bytes([message[message.len() - 2], message[message.len() - 1]]),
            42
        );
    }

    #[test]
    fn chat_round_trip() {
        let data = build_server_chat(3, "hello", true);
        let mut r = Reader::new(&data);
        assert_eq!(r.get_u16().unwrap(), 3);
        assert_eq!(r.get_u16().unwrap(), 5);
        assert_eq!(r.get_bytes(5).unwrap(), b"hello");
        assert!(r.get_bool().unwrap());
    }
}
