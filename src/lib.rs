//! Simple command line client using the [`passivetotal-reqwest`][1] crate to
//! query the [`PassiveTotal`][2] v2 [API][3] via the `reqwest` rust crate.
//!
//! Access to the API is via the `PassiveTotal` struct. This requires a valid
//! `PassiveTotal` username and api key. These can be provided via a
//! configuration file. This is a toml file with the following format:
//!
//! ```
//! [passivetotal]
//! username = "USERNAME"
//! apikey = "SECRET_API_KEY"
//! timeout = <U64>
//! ```
//!
//! The username and apikey fields are required, while the other fields are
//! optional. This file can either be passed as a command line argument or
//! created as `$HOME/.passivetotal.toml`.
//!
//! # Build
//!
//! To build `passivetotal-client` just clone the repository and build it with
//! `cargo`
//!
//! ```ignore
//! git clone https://github.com/alexandg/passivetotal-client
//! cd passivetotal-client
//! cargo build --release
//! ```
//!
//! # Examples
//!
//! Assuming you have the compiled binary in your `$PATH`
//!
//! ## Simple Query
//!
//! ```ignore
//! passivetotal-client pdns "passivetotal.org"
//! ```
//!
//! ## Pretty printing results
//!
//! ```ignore
//! passivetotal-client --pretty pdns "passivetotal.org"
//! ```
//!
//! ## Writing a pretty printed response to a file
//!
//! ```ignore
//! passivetotal-client --pretty -o <PATH TO FILE> pdns "passivetotal.org"
//! ```
//!
//! For a full list of available options and subcommands run
//!
//! ```ignore
//! passivetotal-client --help
//! ```
//!
//! For more information about the options available for a specific subcommand
//! run
//!
//! ```ignore
//! passivetotal-client <COMMAND> --help
//! ```
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
extern crate error_chain;
extern crate passivetotal_reqwest as passivetotal;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json as json;
extern crate structopt;
#[macro_use]
extern crate structopt_derive;
extern crate toml;

use std::io::Write;
use std::fs::File;

use passivetotal::PassiveTotal;

pub mod config;
pub mod opt;

pub mod errors {
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
use opt::{Command, Opt};

fn handle_ssl_command(pt: &PassiveTotal, cmd: &opt::SslCmd) -> Result<json::Value> {
    let result = match *cmd {
        opt::SslCmd::Certificate { ref query } => pt.ssl().certificate(query).send()?,
        opt::SslCmd::History { ref query } => pt.ssl().history(query).send()?,
        opt::SslCmd::Search {
            ref field,
            ref query,
        } => if let Some(f) = field.clone() {
            pt.ssl().search_field(query, f).send()?
        } else {
            pt.ssl().search_keyword(query).send()?
        },
    };

    Ok(result)
}

fn handle_enrichment_command(pt: &PassiveTotal, cmd: &opt::EnrichmentCmd) -> Result<json::Value> {
    let result = match *cmd {
        opt::EnrichmentCmd::Data { ref query } => pt.enrichment().data(query.clone()).send()?,
        opt::EnrichmentCmd::Malware { ref query } => pt.enrichment().malware(query.clone()).send()?,
        opt::EnrichmentCmd::OsInt { ref query } => pt.enrichment().osint(query.clone()).send()?,
        opt::EnrichmentCmd::Subdomains { ref query } => {
            pt.enrichment().subdomains(query.clone()).send()?
        }
    };

    Ok(result)
}

fn handle_actions_command(pt: &PassiveTotal, cmd: &opt::ActionCmd) -> Result<json::Value> {
    let result = match *cmd {
        opt::ActionCmd::Classification { ref query } => pt.actions().classification(query).send()?,
        opt::ActionCmd::Compromised { ref query } => pt.actions().compromised(query).send()?,
        opt::ActionCmd::DynamicDns { ref query } => pt.actions().dynamic_dns(query).send()?,
        opt::ActionCmd::Monitor { ref query } => pt.actions().monitor(query).send()?,
        opt::ActionCmd::Sinkhole { ref query } => pt.actions().sinkhole(query).send()?,
        opt::ActionCmd::Tags { ref query } => pt.actions().tags(query).send()?,
    };

    Ok(result)
}

fn handle_whois_command(pt: &PassiveTotal, cmd: &opt::WhoisCmd) -> Result<json::Value> {
    let result = match *cmd {
        opt::WhoisCmd::Search {
            ref field,
            ref query,
        } => if let Some(f) = field.clone() {
            pt.whois().search_field(query, f).send()?
        } else {
            pt.whois().search_keyword(query).send()?
        },
        opt::WhoisCmd::Data { ref query } => pt.whois().information(query).send()?,
    };

    Ok(result)
}

fn handle_account_command(pt: &PassiveTotal, cmd: &opt::AccountCmd) -> Result<json::Value> {
    let result = match *cmd {
        opt::AccountCmd::Info => pt.account().info().send()?,
        opt::AccountCmd::History => pt.account().history().send()?,
        opt::AccountCmd::Monitors => pt.account().monitors().send()?,
        opt::AccountCmd::Organization => pt.account().organization().send()?,
        opt::AccountCmd::Quotas => pt.account().quota().send()?,
        opt::AccountCmd::Sources { ref source } => {
            pt.account().sources().source(source.clone()).send()?
        }
        opt::AccountCmd::Teamstream => pt.account().organization().teamstream().send()?,
    };

    Ok(result)
}

fn print_response<W>(writer: W, resp: &json::Value, pretty_print: bool) -> Result<()>
where
    W: Write,
{
    if pretty_print {
        json::to_writer_pretty(writer, resp).map_err(|err| err.into())
    } else {
        json::to_writer(writer, resp).map_err(|err| err.into())
    }
}

pub fn print_errors(e: &errors::Error) {
    eprintln!("Error: {}", e);

    for e in e.iter().skip(1) {
        eprintln!("  {}", e);
    }
}

pub fn run(pt: &PassiveTotal, args: &Opt) -> Result<()> {
    let resp = match args.cmd {
        Command::Account(ref cmd) => handle_account_command(pt, cmd)?,
        Command::Action(ref cmd) => handle_actions_command(pt, cmd)?,
        Command::Enrichment(ref cmd) => handle_enrichment_command(pt, cmd)?,
        Command::PassiveDns(ref cmd) => {
            if cmd.unique {
                pt.passive_dns_unique(&cmd.query).send()?
            } else {
                pt.passive_dns(&cmd.query).send()?
            }
        }
        Command::Ssl(ref cmd) => handle_ssl_command(pt, cmd)?,
        Command::Whois(ref cmd) => handle_whois_command(pt, cmd)?,
    };

    match args.output {
        Some(ref path) => {
            let f = File::create(path)?;
            print_response(f, &resp, args.pretty)
        }
        _ => print_response(std::io::stdout(), &resp, args.pretty),
    }
}
