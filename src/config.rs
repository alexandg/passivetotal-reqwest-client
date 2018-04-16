#![allow(unused)]
use std::io::{Read, Write};
use std::env;
use std::fs::File;
use std::time::Duration;
use std::path::{Path, PathBuf};

use toml;

use errors::*;
use passivetotal::{SslField, WhoisField};
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

#[derive(StructOpt)]
pub struct Opt {
    #[structopt(short = "c", long = "config", parse(from_os_str))]
    pub config: Option<PathBuf>,
    #[structopt(short = "p", long = "pretty")]
    pub pretty: bool,
    #[structopt(short = "o", long = "output", parse(from_os_str))]
    pub output: Option<PathBuf>,
    #[structopt(short = "t", long = "timeout", default_value = "60")]
    pub timeout: u64,
    #[structopt(subcommand)]
    pub cmd: Command,
}

#[derive(StructOpt)]
pub enum Command {
    /// Retrieve settins and metadata about your account
    #[structopt(name = "account")]
    Account(AccountCmd),
    /// Retrieve action status information for given query
    #[structopt(name = "actions")]
    Action(ActionCmd),
    /// Get additional enrichment information about a query
    #[structopt(name = "enrichment")]
    Enrichment(EnrichmentCmd),
    /// Retrieve the passive DNS results from active sources
    #[structopt(name = "pdns")]
    PassiveDns(PdnsCmd),
    /// Retrieve information about an SSL certificate
    Ssl(SslCmd),
    /// Retrieve or search WHOIS data for a given query
    Whois(WhoisCmd),
}

/// Retrieve settins and metadata about your account
#[derive(StructOpt)]
pub enum AccountCmd {
    /// Read current account metadata and settings
    #[structopt(name = "info")]
    Info,
    /// Read API usage history of the account
    #[structopt(name = "history")]
    History,
    /// Get active monitors for account
    #[structopt(name = "monitors")]
    Monitors,
    /// Read current organization metadata
    #[structopt(name = "organization")]
    Organization,
    /// Read current account and organization quotas
    #[structopt(name = "quotas")]
    Quotas,
    /// Check sources being used for queries
    #[structopt(name = "sources")]
    Sources { source: String },
    /// Read teamstream activity
    #[structopt(name = "teamstream")]
    Teamstream,
}

/// Retrieve action status information for given query
#[derive(StructOpt)]
pub enum ActionCmd {
    /// Retrieve classification status for a given domain
    #[structopt(name = "classification")]
    Classification {
        /// Domain for which to retrieve classification status
        query: String,
    },
    /// Indicates whether or not a given domain has ever been compromised
    #[structopt(name = "compromised")]
    Compromised {
        /// Domain for which to retrieve classification status.
        query: String,
    },
    #[structopt(name = "ddns")]
    /// Indicates whether or not a domain's DNS records are updated via dynamic DNS
    DynamicDns {
        /// Domain for which to retrieve dynamic DNS status.
        query: String,
    },
    /// Indicates whether or not a domain is monitored
    #[structopt(name = "monitor")]
    Monitor {
        /// Domain for which to check for monitoring.
        query: String,
    },
    /// Indicates whether or not an IP address is a sinkhole
    #[structopt(name = "sinkhole")]
    Sinkhole {
        /// IP address to check for sinkhole status
        query: String,
    },
    /// Retrieves tags for a given artifact
    #[structopt(name = "tags")]
    Tags {
        /// Artifact for which to retrieve tags"
        query: String,
    },
}

/// Get additional enrichment information about a query
#[derive(StructOpt)]
pub enum EnrichmentCmd {
    /// Get enrichment data for a query
    #[structopt(name = "data")]
    Data {
        /// Domain or IP to query.
        query: String,
    },
    /// Get malware data for a query
    #[structopt(name = "malware")]
    Malware {
        /// Domain or IP to query.
        query: String,
    },
    /// Get osint data for a query
    #[structopt(name = "osint")]
    OsInt {
        /// Domain or IP to query.
        query: String,
    },
    /// Get subdomains data for a query
    #[structopt(name = "subdomains")]
    Subdomains {
        /// Domain or IP to query."
        query: String,
    },
}

/// Retrieve the passive DNS results from active sources
#[derive(StructOpt)]
pub struct PdnsCmd {
    /// Query for unique passive dns results
    #[structopt(long = "unique")]
    pub unique: bool,
    /// DNS Query to make
    pub query: String,
}

/// Retrieve information about an SSL certificate
#[derive(StructOpt)]
pub enum SslCmd {
    /// Retrieve an SSL certificate by SHA1 hash
    Certificate {
        /// SHA1 hash of certificate
        query: String,
    },
    /// Retrieve the SSL certificate history of a given SHA1 or IP address
    History {
        /// SHA1 or IP address to retrieve certificate history for
        query: String,
    },
    /// Retrieves SSL certificates for a given search
    Search {
        /// The SSL certificate field to query
        field: Option<SslField>,
        /// Keyword to search for
        query: String,
    },
}

/// Retrieve or search WHOIS data for a given query
#[derive(StructOpt)]
pub enum WhoisCmd {
    /// Retrieve the WHOIS data for given query
    Data {
        /// Domain to query.
        query: String,
    },
    /// Search WHOIS data for a keyword
    Search {
        /// The WHOIS field to query
        field: Option<WhoisField>,
        /// Keyword to search for
        query: String,
    },
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
