
#[cfg(feature = "online")]
extern crate reqwest;

use std::error;
use std::fmt;
#[cfg(feature = "usb")]
use libusb::Error as usbError;
use std::io::Error as ioError;
use std::sync::mpsc::RecvError as channelError;
use base64::DecodeError as base64Error;

#[derive(Debug)]
pub enum YubicoError {
    #[cfg(feature = "online")]
    Network(reqwest::Error),
    #[cfg(feature = "online")]
    HTTPStatusCode(reqwest::StatusCode),
    IOError(ioError),
    ChannelError(channelError),
    DecodeError(base64Error),
    #[cfg(feature = "online-tokio")]
    MultipleErrors(Vec<YubicoError>),
    #[cfg(feature = "usb")]
    UsbError(usbError),
    CommandNotSupported,
    DeviceNotFound,
    OpenDeviceError,
    CanNotWriteToDevice,
    WrongCRC,
    ConfigNotWritten,
    BadOTP,
    ReplayedOTP,
    BadSignature,
    MissingParameter,
    NoSuchClient,
    OperationNotAllowed,
    BackendError,
    NotEnoughAnswers,
    ReplayedRequest,
    UnknownStatus,
    OTPMismatch,
    NonceMismatch,
    SignatureMismatch,
    InvalidKeyLength,
}
            #[cfg(feature = "online-tokio")]

impl fmt::Display for YubicoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            #[cfg(feature = "online")]
            YubicoError::Network(ref err) => write!(f, "Connectivity error: {}", err),
            #[cfg(feature = "online")]
            YubicoError::HTTPStatusCode(code) => write!(f, "Error found: {}", code),
            YubicoError::IOError(ref err) => write!(f, "IO error: {}", err),
            YubicoError::ChannelError(ref err) => write!(f, "Channel error: {}", err),
            YubicoError::DecodeError(ref err) => write!(f, "Decode  error: {}", err),
            #[cfg(feature = "online-tokio")]
            YubicoError::MultipleErrors(ref errs) => {
                write!(f, "Multiple errors. ")?;

                for err in errs {
                    write!(f, "{} ", err)?;
                }

                Ok(())
            }
            #[cfg(feature = "usb")]
            YubicoError::UsbError(ref err) => write!(f, "USB  error: {}", err),                       
            YubicoError::BadOTP => write!(f, "The OTP has invalid format."),
            YubicoError::ReplayedOTP => write!(f, "The OTP has already been seen by the service."),
            YubicoError::BadSignature => write!(f, "The HMAC signature verification failed."),
            YubicoError::MissingParameter => write!(f, "The request lacks a parameter."),
            YubicoError::NoSuchClient => write!(f, "The request id does not exist."),
            YubicoError::OperationNotAllowed => write!(f, "The request id is not allowed to verify OTPs."),
            YubicoError::BackendError => write!(f, "Unexpected error in our server. Please contact us if you see this error."),
            YubicoError::NotEnoughAnswers => write!(f, "Server could not get requested number of syncs during before timeout"),
            YubicoError::ReplayedRequest => write!(f, "Server has seen the OTP/Nonce combination before"),
            YubicoError::UnknownStatus => write!(f, "Unknown status sent by the OTP validation server"),
            YubicoError::OTPMismatch => write!(f, "OTP mismatch, It may be an attack attempt"),
            YubicoError::NonceMismatch => write!(f, "Nonce mismatch, It may be an attack attempt"),
            YubicoError::SignatureMismatch => write!(f, "Signature mismatch, It may be an attack attempt"),
            YubicoError::DeviceNotFound => write!(f, "Device not found"),
            YubicoError::OpenDeviceError => write!(f, "Can not open device"),
            YubicoError::CommandNotSupported => write!(f, "Command Not Supported"),
            YubicoError::WrongCRC => write!(f, "Wrong CRC"),            
            YubicoError::CanNotWriteToDevice => write!(f, "Can not write to Device"),
            YubicoError::ConfigNotWritten => write!(f, "Configuration has failed"),
            YubicoError::InvalidKeyLength => write!(f, "Invalid key length encountered while building signature"),
        }
    }
}

impl error::Error for YubicoError {
    fn description(&self) -> &str {
        match *self {
            #[cfg(feature = "online")]
            YubicoError::Network(ref err) => err.description(),
            #[cfg(feature = "online")]
            YubicoError::HTTPStatusCode(_) => "200 not received",
            YubicoError::IOError(ref err) => err.description(),
            YubicoError::ChannelError(ref err) => err.description(),
            YubicoError::DecodeError(ref err) => err.description(),
            #[cfg(feature = "online-tokio")]
            YubicoError::MultipleErrors(ref _errs) => {
                "Multiple errors. "
            }
            #[cfg(feature = "usb")]
            YubicoError::UsbError(ref err) => err.description(),            
            YubicoError::BadOTP => "The OTP has invalid format.",
            YubicoError::ReplayedOTP => "The OTP has already been seen by the service.",
            YubicoError::BadSignature => "The HMAC signature verification failed.",
            YubicoError::MissingParameter => "The request lacks a parameter.",
            YubicoError::NoSuchClient => "The request id does not exist.",
            YubicoError::OperationNotAllowed => "The request id is not allowed to verify OTPs.",
            YubicoError::BackendError => "Unexpected error in our server. Please contact us if you see this error.",
            YubicoError::NotEnoughAnswers => "Server could not get requested number of syncs during before timeout",
            YubicoError::ReplayedRequest => "Server has seen the OTP/Nonce combination before",
            YubicoError::UnknownStatus => "Unknown status sent by the OTP validation server",
            YubicoError::OTPMismatch => "OTP in the response is the same as the supplied in the request. It may be an attack attempt",
            YubicoError::NonceMismatch => "Nonce in the response is the same as the supplied in the request. It may be an attack attempt",
            YubicoError::SignatureMismatch => "Signature in the response is the same as the supplied in the request. It may be an attack attempt",
            YubicoError::DeviceNotFound => "Yubikey device not found",
            YubicoError::OpenDeviceError => "Can not open device",
            YubicoError::CommandNotSupported => "Command Not Supported",
            YubicoError::WrongCRC => "Wrong CRC",            
            YubicoError::CanNotWriteToDevice => "Can not write to Device", 
            YubicoError::ConfigNotWritten => "Can configure the Device",
            YubicoError::InvalidKeyLength => "Invalid key length",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            #[cfg(feature = "online")]
            YubicoError::Network(ref err) => Some(err),
            #[cfg(feature = "online")]
            YubicoError::HTTPStatusCode(_) => None,
            YubicoError::IOError(ref err) => Some(err),
            YubicoError::ChannelError(ref err) => Some(err),
            YubicoError::DecodeError(ref err) => Some(err),
            #[cfg(feature = "online-tokio")]
            YubicoError::MultipleErrors(ref errs) => {
                match errs.first() {
                    Some(err) => Some(err),
                    None => None
                }
            },
            #[cfg(feature = "usb")]
            YubicoError::UsbError(ref err) => Some(err),                    
            _ => None
        }
    }
}

#[cfg(feature = "online")]
impl From<reqwest::Error> for YubicoError {
    fn from(err: reqwest::Error) -> YubicoError {
        YubicoError::Network(err)
    }
}

#[cfg(feature = "online")]
impl From<reqwest::StatusCode> for YubicoError {
    fn from(err: reqwest::StatusCode) -> YubicoError {
        YubicoError::HTTPStatusCode(err)
    }
}

impl From<ioError> for YubicoError {
    fn from(err: ioError) -> YubicoError {
        YubicoError::IOError(err)
    }
}

impl From<channelError> for YubicoError {
    fn from(err: channelError) -> YubicoError {
        YubicoError::ChannelError(err)
    }
}

impl From<base64Error> for YubicoError {
    fn from(err: base64Error) -> YubicoError {
        YubicoError::DecodeError(err)
    }
}

#[cfg(feature = "usb")]
impl From<usbError> for YubicoError {
    fn from(err: usbError) -> YubicoError {
        YubicoError::UsbError(err)
    }
}