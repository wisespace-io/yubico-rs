use yubicoerror::YubicoError;
use hidapi::{HidApi, HidDevice};
use std::{thread, time};

#[allow(dead_code)]
const SLOT_DATA_SIZE: usize = 64;

pub fn open(api: &HidApi, vendor_id: u16, product_id: u16) -> Result<HidDevice, YubicoError> {
    for _ in 0..5 {
        if let Ok(handler) = api.open(vendor_id, product_id) {
            return Ok(handler);
        }
        thread::sleep(time::Duration::from_millis(1000));
    }
     Err(YubicoError::OpenDeviceError)
}

#[allow(dead_code)]
pub struct Frame {
    payload: [u8; SLOT_DATA_SIZE],
    filler: [u8; 3],
    crc: u16,
}

impl Frame {
    #[allow(dead_code)]
    pub fn new(payload: [u8; 64]) -> Self {
        let frame = Frame {
            payload: payload,
            filler: [0; 3],
            crc: 0,
        };
        frame
    }
}

#[allow(dead_code)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CommandType {
    Config = 0x01,
    Config2 = 0x03,
    Update1 = 0x04,
    Update2 = 0x05,
    DeviceSerial = 0x10,
    DeviceConfig = 0x11,
    ChallengeHmac1 = 0x30,
    ChallengeHmac2 = 0x38,
    Error = 0x7f,
}

impl CommandType {
    #[allow(dead_code)]
    pub fn from_u8(byte: u8) -> CommandType {
        match byte {
            0x01 => CommandType::Config,
            0x03 => CommandType::Config2,
            0x04 => CommandType::Update1,
            0x05 => CommandType::Update2,
            0x10 => CommandType::DeviceSerial,
            0x11 => CommandType::DeviceConfig,
            0x30 => CommandType::ChallengeHmac1,
            0x38 => CommandType::ChallengeHmac2,
            _ => CommandType::Error,
        }
    }

    #[allow(dead_code)]
    pub fn to_u8(&self) -> u8 {
        *self as u8
    }
}