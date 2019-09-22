use std::fmt::Display;

static API1_HOST: &'static str = "https://api.yubico.com/wsapi/2.0/verify";
static API2_HOST: &'static str = "https://api2.yubico.com/wsapi/2.0/verify";
static API3_HOST: &'static str = "https://api3.yubico.com/wsapi/2.0/verify";
static API4_HOST: &'static str = "https://api4.yubico.com/wsapi/2.0/verify";
static API5_HOST: &'static str = "https://api5.yubico.com/wsapi/2.0/verify";

#[derive(Clone, Debug, PartialEq)]
pub enum Slot {
    Slot1,
    Slot2,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Mode {
    Sha1,
    Otp,
}

/// From the Validation Protocol documentation:
///
/// A value 0 to 100 indicating percentage of syncing required by client,
/// or strings "fast" or "secure" to use server-configured values; if
/// absent, let the server decide.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct SyncLevel(u8);

impl SyncLevel {
    pub fn fast() -> SyncLevel {
        SyncLevel(0)
    }

    pub fn secure() -> SyncLevel {
        SyncLevel(100)
    }

    pub fn custom(level: u8) -> SyncLevel {
        if level > 100 {
            SyncLevel(100)
        } else {
            SyncLevel(level)
        }
    }
}

impl Display for SyncLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    pub client_id: String,
    pub key: Vec<u8>,
    pub api_hosts: Vec<String>,
    pub user_agent: String,
    pub sync_level: SyncLevel,
}

#[allow(dead_code)]
impl Config {
    pub fn default() -> Config {
        Config {
            client_id: String::new(),
            key: Vec::new(),
            api_hosts: build_hosts(),
            user_agent: "github.com/wisespace-io/yubico-rs".to_string(),
            sync_level: SyncLevel::secure(),
        }
    }

    pub fn set_client_id<C>(mut self, client_id: C) -> Self
    where
        C: Into<String>,
    {
        self.client_id = client_id.into();
        self
    }

    pub fn set_key<K>(mut self, key: K) -> Self
    where
        K: Into<String>,
    {
        self.key = key.into().into_bytes();
        self
    }

    pub fn set_api_hosts(mut self, hosts: Vec<String>) -> Self {
        self.api_hosts = hosts;
        self
    }

    pub fn set_user_agent(mut self, user_agent: String) -> Self {
        self.user_agent = user_agent;
        self
    }

    pub fn set_sync_level(mut self, level: SyncLevel) -> Self {
        self.sync_level = level;
        self
    }
}

fn build_hosts() -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();

    hosts.push(API1_HOST.to_string());
    hosts.push(API2_HOST.to_string());
    hosts.push(API3_HOST.to_string());
    hosts.push(API4_HOST.to_string());
    hosts.push(API5_HOST.to_string());

    hosts
}
