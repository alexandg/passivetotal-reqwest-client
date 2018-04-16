use std::io::{Read};
use std::env;
use std::fs::File;
use std::path::{Path, PathBuf};

use toml;

use errors::*;
use opt::Opt;
use Result;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub passivetotal: PassiveTotalConfig,
}

#[derive(Debug, Deserialize)]
pub struct PassiveTotalConfig {
    pub username: String,
    pub apikey: String,
    pub timeout: Option<u64>,
}

impl Config {
    pub fn from_opt(opt: &Opt) -> Result<Config> {
        match opt.config.clone().or_else(default_config) {
            Some(ref cfg_path) => load_config(cfg_path),
            None => Err("Unable to find valid configuration file.".into()),
        }
    }
}

fn default_config() -> Option<PathBuf> {
    env::home_dir().map(|mut home| {
        home.push(".passivetotal.toml");
        home
    })
}

fn load_config<P: AsRef<Path>>(config: P) -> Result<Config> {
    let mut s = String::new();
    File::open(config)
        .and_then(|mut f| f.read_to_string(&mut s))
        .chain_err(|| "Failed to open config file.")?;

    toml::from_str(&s).chain_err(|| "Unable to parse configuration file.")
}
