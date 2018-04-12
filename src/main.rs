//! Simple command line client using the [`passivetotal-reqwest`][1] crate to
//! query the [`PassiveTotal`][2] v2 [API][3] via the `reqwest` rust crate.
//!
//! Access to the API is via the `PassiveTotal` struct. This requires a valid
//! `PassiveTotal` username and api key. These can either be provided via a
//! configuration file. This is a toml file with the following format:
//!
//! ```
//! [passivetotal]
//! username = "USERNAME"
//! apikey = "SECRET_API_KEY"
//! timeout = 60
//! ```
//!
//! The username and apikey fields are required, while the other fields are
//! optional. This file can either be passed as a command line argument or
//! created as `$HOME/.passivetotal.toml`.
//!
//! # License
//!
//! `passivetotal-client` is licensed under the MIT License. See LICENSE.
//!
//! [1]: https://github.com/alexandg/passivetotal-reqwest
//! [2]: https://www.passivetotal.org
//! [3]: https://api.passivetotal.org/api/docs/
#![recursion_limit = "1024"]
#[macro_use]
extern crate clap;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate serde_derive;

extern crate serde;
extern crate serde_json as json;
extern crate toml;

extern crate passivetotal_reqwest as passivetotal;

use std::io::{Read, Write};
use std::env;
use std::fs::File;
use std::time::Duration;
use std::path::{Path, PathBuf};

use clap::ArgMatches;
use passivetotal::PassiveTotal;

const ABOUT: &str = "Simple CLI for passivetotal-reqwest library.";

mod errors {
    use std::io;
    use json;
    use passivetotal;

    error_chain! {
        foreign_links {
            Pt(passivetotal::PassiveTotalError);
            Io(io::Error);
            Json(json::Error);
        }
    }
}

use errors::*;

#[derive(Debug, Deserialize)]
struct Config {
    passivetotal: PassiveTotalConfig,
}

#[derive(Debug, Deserialize)]
struct PassiveTotalConfig {
    username: String,
    apikey: String,
    timeout: Option<u64>,
}

fn parse_args() -> ArgMatches<'static> {
    clap_app!(passivetotal =>
        (version: crate_version!())
        (about: ABOUT)
        (@arg CONFIG: -c --config +takes_value "Choose a specific config file. \
                                                Default $HOME/.passivetotal.toml.")
        (@arg TIMEOUT: -t --timeout +takes_value "Timeout for all requests.")
        (@arg OUTPUT: -o --output +takes_value "File to write output to.")
        (@arg PRETTY: -p --pretty "Pretty print JSON results.")
        (@subcommand pdns =>
         (about: "Retrieve the passive DNS results from active sources.")
         (@arg UNIQUE: --unique "Query for unique passive dns results.")
         (@arg QUERY: +required "DNS Query to make."))
        (@subcommand whois =>
         (about: "Retrieve or search WHOIS data for a given query.")
         (@subcommand data =>
          (about: "Retrieve the WHOIS data for given query.")
          (@arg QUERY: +required "Domain to query."))
         (@subcommand search =>
          (about: "Search WHOIS data for a keyword.")
          (@arg FIELD: --field +takes_value "The field to query. [Email, Domain, Name, \
                                             Organization, Address, Phone, Nameserver]")
          (@arg QUERY: +required "Keyword to search for.")))
        (@subcommand ssl =>
         (about: "Retrieve information about an SSL certificate.")
         (@subcommand certificate =>
          (about: "Retrieve an SSL certificate by SHA1 hash")
          (@arg QUERY: +required "SHA1 hash of certificate."))
         (@subcommand search =>
          (about: "Retrieves SSL certificates for a given search.")
          (@arg FIELD: --field +takes_value "The field to query. See the Passivetotal \
                                             API for a full list of fields.")
          (@arg QUERY: +required "Keyword to search for."))
         (@subcommand history =>
          (about: "Retrieve the SSL certificate history of a given SHA1 or IP address.")
          (@arg QUERY: +required "SHA1 or IP address to retrieve certificate history for.")))
        (@subcommand enrichment =>
         (about: "Get additional enrichment information about a query.")
         (@subcommand data =>
          (about: "Get enrichment data for a query.")
          (@arg QUERY: +required "Domain or IP to query."))
         (@subcommand malware =>
          (about: "Get malware data for a query.")
          (@arg QUERY: +required "Domain or IP to query."))
         (@subcommand osint =>
          (about: "Get osint data for a query.")
          (@arg QUERY: +required "Domain or IP to query."))
         (@subcommand subdomains =>
          (about: "Get subdomains data for a query.")
          (@arg QUERY: +required "Domain or IP to query.")))
        (@subcommand actions =>
         (about: "Retrieve action status information for given query.")
         (@subcommand classification =>
          (about: "Retrieve classification status for a given domain.")
          (@arg QUERY: +required "Domain for which to retrieve classification status."))
         (@subcommand compromised =>
          (about: "Indicates whether or not a given domain has ever been compromised.")
          (@arg QUERY: +required "Domain for which to retrieve classification status."))
         (@subcommand ddns =>
          (about: "Indicates whether or not a domain's DNS records are updated via dynamic DNS.")
          (@arg QUERY: +required "Domain for which to retrieve dynamic DNS status."))
         (@subcommand monitor =>
          (about: "Indicates whether or not a domain is monitored.")
          (@arg QUERY: +required "Domain for which to check for monitoring."))
         (@subcommand sinkhole =>
          (about: "Indicates whether or not an IP address is a sinkhole.")
          (@arg QUERY: +required "IP address to check for sinkhole status"))
         (@subcommand tags =>
          (about: "Retrieves tags for a given artifact.")
          (@arg QUERY: +required "Artifact for which to retrieve tags")))
        (@subcommand account =>
         (about: "Retrieve settings and metadata about your account.")
         (@subcommand info =>
          (about: "Read current account metadata and settings."))
         (@subcommand history =>
          (about: "Read API usage history of the account."))
         (@subcommand monitors =>
          (about: "Get active monitors for account."))
         (@subcommand organization =>
          (about: "Read current organization metadata."))
         (@subcommand quotas =>
          (about: "Read current account and organization quotas."))
         (@subcommand sources =>
          (about: "Check sources being used for queries.")
          (@arg SOURCE: +takes_value +required "Specific source to check"))
         (@subcommand teamstream =>
          (about: "Read team activity."))
         )
    ).get_matches()
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

fn config(args: &ArgMatches) -> Result<Config> {
    args.value_of("CONFIG")
        .map(PathBuf::from)
        .or_else(default_config)
        .ok_or_else(|| "Unable to find valid configuration filepath!".into())
        .and_then(load_config)
}

fn handle_ssl_command(pt: &PassiveTotal, cmd: &ArgMatches) -> Result<json::Value> {
    let result = match cmd.subcommand() {
        ("certificate", Some(c)) => {
            let query = c.value_of("QUERY").unwrap();
            pt.ssl().certificate(query).send()?
        },
        ("history", Some(c)) => {
            let query = c.value_of("QUERY").unwrap();
            pt.ssl().history(query).send()?
        },
        ("search", Some(c)) => {
            let query = c.value_of("QUERY").unwrap();
            if let Some(f) = c.value_of("FIELD") {
                match f.parse() {
                    Ok(field) => pt.ssl().search_field(query, field).send()?,
                    Err(err) => return Err(err.into()),
                }
            } else {
                pt.ssl().search_keyword(query).send()?
            }
        },
        _ => return Err("No valid subcommand provided to `ssl` command!".into()),
    };

    Ok(result)
}

fn handle_enrichment_command(pt: &PassiveTotal, cmd: &ArgMatches) -> Result<json::Value> {
    let result = match cmd.subcommand() {
        ("data", Some(c)) => {
            let query = c.value_of("QUERY").unwrap();
            pt.enrichment().data(query).send()?
        },
        ("malware", Some(c)) => {
            let query = c.value_of("QUERY").unwrap();
            pt.enrichment().malware(query).send()?
        },
        ("osint", Some(c)) => {
            let query = c.value_of("QUERY").unwrap();
            pt.enrichment().osint(query).send()?
        },
        ("subdomains", Some(c)) => {
            let query = c.value_of("QUERY").unwrap();
            pt.enrichment().subdomains(query).send()?
        },
        _ => return Err("No valid subcommand provided to `enrichment` command!".into()),
    };

    Ok(result)
}

fn handle_actions_command(pt: &PassiveTotal, cmd: &ArgMatches) -> Result<json::Value> {
    let result = match cmd.subcommand() {
        ("classification", Some(c)) => {
            let query = c.value_of("QUERY").unwrap();
            pt.actions().classification(query).send()?
        },
        ("compromised", Some(c)) => {
            let query = c.value_of("QUERY").unwrap();
            pt.actions().compromised(query).send()?
        },
        ("ddns", Some(c)) => {
            let query = c.value_of("QUERY").unwrap();
            pt.actions().dynamic_dns(query).send()?
        },
        ("monitor", Some(c)) => {
            let query = c.value_of("QUERY").unwrap();
            pt.actions().monitor(query).send()?
        },
        ("sinkhole", Some(c)) => {
            let query = c.value_of("QUERY").unwrap();
            pt.actions().sinkhole(query).send()?
        },
        ("tags", Some(c)) => {
            let query = c.value_of("QUERY").unwrap();
            pt.actions().tags(query).send()?
        },
        _ => return Err("No valid subcommand provided to `actions` command!".into()),
    };

    Ok(result)
}

fn handle_whois_command(pt: &PassiveTotal, cmd: &ArgMatches) -> Result<json::Value> {
    let result = match cmd.subcommand() {
        ("search", Some(c)) => {
            let query = c.value_of("QUERY").unwrap();
            if let Some(f) = c.value_of("FIELD") {
                match f.parse() {
                    Ok(field) => pt.whois().search_field(query, field).send()?,
                    Err(err) => return Err(err.into()),
                }
            } else {
                pt.whois().search_keyword(query).send()?
            }
        },
        ("data", Some(c)) => {
            let query = c.value_of("QUERY").unwrap();
            pt.whois().information(query).send()?
        },
        _ => return Err("No valid subcommand provided to `whois` command!".into()),
    };

    Ok(result)
}

fn handle_account_command(pt: &PassiveTotal, cmd: &ArgMatches) -> Result<json::Value> {
    let result = match cmd.subcommand() {
        ("info", _) => pt.account().info().send()?,
        ("history", _) => pt.account().history().send()?,
        ("monitors", _) => pt.account().monitors().send()?,
        ("organization", _) => pt.account().organization().send()?,
        ("quotas", _) => pt.account().quota().send()?,
        ("sources", Some(cmd)) => {
            let source = cmd.value_of("SOURCE").unwrap();
            pt.account().sources().source(source).send()?
        },
        ("teamstream", _) => pt.account().organization().teamstream().send()?,
        _ => return Err("No valid subcommand provided to `account` command!".into()),
    };

    Ok(result)
}

fn run(pt: &PassiveTotal, args: &ArgMatches) -> Result<()> {
    // Calling unwrap on all these checks for 'QUERY' are ok because 'QUERY' is
    // always required in each case so a value MUST exist.
    let resp = match args.subcommand() {
        ("pdns", Some(cmd)) => {
            let query = cmd.value_of("QUERY").unwrap();
            if cmd.is_present("UNIQUE") {
                pt.passive_dns_unique(query).send()?
            } else {
                pt.passive_dns(query).send()?
            }
        },
        ("whois", Some(cmd)) => handle_whois_command(pt, cmd)?,
        ("ssl", Some(cmd)) => handle_ssl_command(pt, cmd)?,
        ("enrichment", Some(cmd)) => handle_enrichment_command(pt, cmd)?,
        ("actions", Some(cmd)) => handle_actions_command(pt, cmd)?,
        ("account", Some(cmd)) => handle_account_command(pt, cmd)?,
        _ => return Err("No valid command provided!".into()),
    };

    let pretty = args.is_present("PRETTY");
    Ok(match args.value_of("OUTPUT") {
        Some(file) => {
            let f = File::create(file)?;
            print_response(f, &resp, pretty)?
        },
        _ => print_response(std::io::stdout(), &resp, pretty)?,
    })
}

fn print_response<W>(writer: W, resp: &json::Value, pretty_print: bool) -> Result<()>
where
    W: Write,
{
    Ok(if pretty_print {
        json::to_writer_pretty(writer, resp)?
    } else {
        json::to_writer(writer, resp)?
    })
}

fn print_errors(e: &errors::Error) {
    eprintln!("Error: {}", e);

    for e in e.iter().skip(1) {
        eprintln!("  {}", e);
    }
}

fn main() {
    let args = parse_args();

    let config = match config(&args) {
        Ok(cfg) => cfg,
        Err(ref e) => {
            print_errors(e);
            return;
        },
    };

    let timeout = value_t!(args, "TIMEOUT", u64)
        .ok()
        .or(config.passivetotal.timeout)
        .unwrap_or(60);

    let pt = PassiveTotal::new(
        config.passivetotal.username,
        config.passivetotal.apikey,
        Duration::from_secs(timeout),
    );

    if let Err(ref e) = run(&pt, &args) {
        print_errors(e);
    }
}
