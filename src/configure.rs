use std;
use hmacmode::{ HmacKey };
use otpmode::{ Aes128Key };
use sec::{ crc16 };
use manager::{ Command, Frame };

const FIXED_SIZE: usize = 16;
const UID_SIZE: usize = 6;
const KEY_SIZE: usize = 16;
const ACC_CODE_SIZE: usize = 6;

/// The configuration of a YubiKey.
#[repr(C)]
#[repr(packed)]
pub struct DeviceConfig {
    pub fixed: [u8; FIXED_SIZE],
    pub uid: [u8; UID_SIZE],
    pub key: [u8; KEY_SIZE],
    pub acc_code: [u8; ACC_CODE_SIZE],
    pub fixed_size: u8,
    pub ext_flags: ExtendedFlags,
    pub tkt_flags: TicketFlags,
    pub cfg_flags: ConfigFlags,
    pub rfu: [u8; 2],
    pub crc: u16,
}

impl std::default::Default for DeviceConfig {
    fn default() -> Self {
        DeviceConfig {
            fixed: [0; FIXED_SIZE],
            uid: [0; UID_SIZE],
            key: [0; KEY_SIZE],
            acc_code: [0; ACC_CODE_SIZE],
            fixed_size: 0,
            ext_flags: ExtendedFlags::empty(),
            tkt_flags: TicketFlags::empty(),
            cfg_flags: ConfigFlags::empty(),
            rfu: [0; 2],
            crc: 0,
        }
    }
}

const SIZEOF_CONFIG: usize = 52;

impl DeviceConfig {

    #[doc(hidden)]
    pub fn to_frame(&mut self, command: Command) -> Frame {
        let mut payload = [0; 64];
        // First set CRC.
        self.crc = {
            let first_fields = unsafe {
                std::slice::from_raw_parts(self as *const DeviceConfig as *const u8, SIZEOF_CONFIG - 2)
            };
            (0xffff - crc16(&first_fields)).to_le()
        };

        // Then write to the payload.
        let s = unsafe {
            std::slice::from_raw_parts(self as *const DeviceConfig as *const u8, SIZEOF_CONFIG)
        };
        (&mut payload[..SIZEOF_CONFIG]).clone_from_slice(s);

        Frame::new(payload, command)
    }

    /// Sets the configuration in challenge-response, HMAC-SHA1
    /// mode. This mode has two sub-modes: if `variable` is `true`,
    /// the challenges can be of variable length up to 63 bytes. Else,
    /// all challenges must be exactly 64 bytes long.
    pub fn challenge_response_hmac(&mut self, secret: &HmacKey, variable: bool, button:bool) {
        self.tkt_flags = TicketFlags::empty();
        self.cfg_flags = ConfigFlags::empty();
        self.ext_flags = ExtendedFlags::empty();

        self.tkt_flags.insert(TicketFlags::CHAL_RESP);
        self.cfg_flags.insert(if button { ConfigFlags::CHAL_HMAC | ConfigFlags::CHAL_BTN_TRIG } else { ConfigFlags::CHAL_HMAC });
        if variable {
            self.cfg_flags.insert(ConfigFlags::HMAC_LT64)
        } else {
            self.cfg_flags.remove(ConfigFlags::HMAC_LT64)
        }
        let (a, b) = secret.0.split_at(16);
        self.key.copy_from_slice(a);
        (&mut self.uid[..4]).copy_from_slice(b);
    }

    /// Sets the configuration in challenge-response, OTP mode.
    pub fn challenge_response_otp(&mut self, secret: &Aes128Key, priv_id: &[u8;6], button: bool) {
        self.tkt_flags = TicketFlags::empty();
        self.cfg_flags = ConfigFlags::empty();
        self.ext_flags = ExtendedFlags::empty();

        self.tkt_flags.insert(TicketFlags::CHAL_RESP);
        self.cfg_flags.insert(if button { ConfigFlags::CHAL_YUBICO | ConfigFlags::CHAL_BTN_TRIG } else { ConfigFlags::CHAL_YUBICO });

        self.uid.copy_from_slice(priv_id);
        self.key.copy_from_slice(&secret.0);
    }
}

bitflags! {
    pub struct TicketFlags: u8 {
        const TAB_FIRST = 0x1;
        const APPEND_TAB1 = 0x2;
        const APPEND_TAB2 = 0x4;
        const APPEND_DELAY1 = 0x8;
        const APPEND_DELAY2 = 0x10;
        const APPEND_CR = 0x20;
        const OATH_HOTP = 0x40;
        const CHAL_RESP = 0x40;
        const PROTECT_CFG2 = 0x80;
    }
}

bitflags! {
    pub struct ConfigFlags: u8 {
        // Yubikey 1.0
        const SEND_REF = 0x1;
        const TICKET_FIRST = 0x2;
        const PACING_10MS = 0x4;
        const PACING_20MS = 0x8;
        const STATIC_TICKET = 0x20;
        // YubiKey >= 2.0
        const SHORT_TICKET = 0x2;
        const STRONG_PW1 = 0x10;
        const STRONG_PW2 = 0x40;
        const MAN_UPDATE = 0x80;
        // YubiKey >= 2.1
        const OATH_HOTP8 = 0x2;
        const OATH_FIXED_MODHEX1 = 0x10;
        const OATH_FIXED_MODHEX2 = 0x40;
        const OATH_FIXED_MODHEX = 0x50;
        const OATH_FIXED_MASK = 0x50;
        // YubiKey >= 2.2
        const CHAL_YUBICO = 0x20;
        const CHAL_HMAC = 0x22;
        const HMAC_LT64 = 0x04;
        const CHAL_BTN_TRIG = 0x08;
    }
}

bitflags! {
    pub struct ExtendedFlags: u8 {
        const SERIAL_BTN_VISIBLE = 0x01;
        const SERIAL_USB_VISIBLE = 0x02;
        const SERIAL_API_VISIBLE = 0x04;
        // YubiKey >= 2.3
        const USE_NUMERIC_KEYPAD = 0x08;
        const FAST_TRIG = 0x10;
        const ALLOW_UPDATE = 0x20;
        const DORMANT = 0x40;
    }
}