use serde::Deserialize;

#[derive(Deserialize, Clone)]
pub struct Config {
    pub server: Server,
    pub dns_servers: Vec<DnsServer>,
}

#[derive(Deserialize, Clone)]
pub struct Server {
    pub host: String,
    pub port: u16,
}

#[derive(Deserialize, Clone)]
pub struct DnsServer {
    pub location: String,
    pub ip: String,
}

pub fn load() -> anyhow::Result<Config> {
    let raw = std::fs::read_to_string("config.toml")?;
    Ok(toml::from_str(&raw)?)
}
