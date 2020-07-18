use std::fmt::Display;
use std::time::Duration;

static API1_HOST: &str = "https://api.yubico.com/wsapi/2.0/verify";
static API2_HOST: &str = "https://api2.yubico.com/wsapi/2.0/verify";
static API3_HOST: &str = "https://api3.yubico.com/wsapi/2.0/verify";
static API4_HOST: &str = "https://api4.yubico.com/wsapi/2.0/verify";
static API5_HOST: &str = "https://api5.yubico.com/wsapi/2.0/verify";

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
    /// The timeout for HTTP requests.
    pub request_timeout: Duration,
    pub proxy_url: String,
    pub proxy_username: String,
    pub proxy_password: String,
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
            request_timeout: Duration::from_secs(30), // Value taken from the reqwest crate.
            proxy_url: String::new(),
            proxy_username: String::new(),
            proxy_password: String::new(),
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

    pub fn set_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    pub fn set_proxy_url<P>(mut self, proxy_url: P) -> Self
    where
        P: Into<String>,
    {
        self.proxy_url = proxy_url.into();
        self
    }  
    
    pub fn set_proxy_username<U>(mut self, proxy_username: U) -> Self
    where
        U: Into<String>,
    {
        self.proxy_username = proxy_username.into();
        self
    }
    
    pub fn set_proxy_password<P>(mut self, proxy_password: P) -> Self
    where
        P: Into<String>,
    {
        self.proxy_password = proxy_password.into();
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
