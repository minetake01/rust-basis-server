//! Server-wide feature locks mirrored from BasisGlobalLockManager.

#[derive(Debug, Clone, Copy, Default)]
pub struct GlobalLocks {
    pub avatars: bool,
    pub props: bool,
    pub worlds: bool,
    pub servers: bool,
    pub third_person: bool,
    pub additional_avatar_data: bool,
    pub camera_metadata_mask: u8,
    pub user_restriction_mode: u8,
    pub playspace_mover: bool,
    pub direct_connect: bool,
    pub cilbox: bool,
    pub images: bool,
    pub end_effector_ik_disabled: bool,
    pub text_chat: bool,
    pub voice_chat: bool,
    pub media_player: bool,
    pub camera_capture: bool,
    pub prop_grabbing: bool,
    pub safe_display_names: bool,
    pub gifs: bool,
    pub content_removal: bool,
    pub external_links: bool,
}

impl GlobalLocks {
    /// AdminRequestMode.GlobalGetLockState payload.
    pub fn payload(&self) -> Vec<u8> {
        vec![
            21,
            u8::from(self.avatars),
            u8::from(self.props),
            u8::from(self.worlds),
            u8::from(self.servers),
            u8::from(self.third_person),
            u8::from(self.additional_avatar_data),
            self.camera_metadata_mask,
            self.user_restriction_mode,
            u8::from(self.playspace_mover),
            u8::from(self.direct_connect),
            u8::from(self.cilbox),
            u8::from(self.images),
            u8::from(self.end_effector_ik_disabled),
            u8::from(self.text_chat),
            u8::from(self.voice_chat),
            u8::from(self.media_player),
            u8::from(self.camera_capture),
            u8::from(self.prop_grabbing),
            u8::from(self.safe_display_names),
            u8::from(self.gifs),
            u8::from(self.content_removal),
            u8::from(self.external_links),
        ]
    }

    /// Applies one AdminRequestMode toggle and returns the new locked state.
    pub fn toggle(&mut self, mode: u8) -> Option<bool> {
        let slot = match mode {
            18 => &mut self.avatars,
            19 => &mut self.props,
            20 => &mut self.worlds,
            37 => &mut self.servers,
            38 => &mut self.third_person,
            41 => &mut self.additional_avatar_data,
            53 => &mut self.playspace_mover,
            54 => &mut self.direct_connect,
            59 => &mut self.cilbox,
            60 => &mut self.images,
            66 => &mut self.end_effector_ik_disabled,
            67 => &mut self.text_chat,
            68 => &mut self.voice_chat,
            69 => &mut self.media_player,
            70 => &mut self.camera_capture,
            71 => &mut self.prop_grabbing,
            72 => &mut self.safe_display_names,
            92 => &mut self.gifs,
            96 => &mut self.content_removal,
            97 => &mut self.external_links,
            _ => return None,
        };
        *slot = !*slot;
        Some(*slot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_state_payload_has_csharp_order_and_length() {
        let locks = GlobalLocks {
            text_chat: true,
            camera_metadata_mask: 3,
            ..Default::default()
        };
        let payload = locks.payload();
        assert_eq!(payload.len(), 23);
        assert_eq!(payload[0], 21);
        assert_eq!(payload[7], 3);
        assert_eq!(payload[14], 1);
    }

    #[test]
    fn admin_toggle_modes_flip_the_right_flag() {
        let mut locks = GlobalLocks::default();
        assert_eq!(locks.toggle(67), Some(true));
        assert!(locks.text_chat);
        assert_eq!(locks.toggle(67), Some(false));
        assert!(!locks.text_chat);
        assert_eq!(locks.toggle(18), Some(true));
        assert!(locks.avatars);
        assert_eq!(locks.toggle(200), None);
    }
}
