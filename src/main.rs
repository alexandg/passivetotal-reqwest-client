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
// TODO Remove all the nasty clones
#![recursion_limit = "1024"]
#[macro_use]
extern crate error_chain;
extern crate passivetotal_reqwest as passivetotal;
#[macro_use]
extern crate serde_derive;
extern crate structopt;
#[macro_use]
extern crate structopt_derive;
extern crate serde;
extern crate serde_json as json;
extern crate toml;

use std::io::{Write};
use std::fs::File;
use std::time::Duration;

use passivetotal::PassiveTotal;
use structopt::StructOpt;

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

mod config;

use config::{Command, Config, Opt};
use errors::*;

fn handle_ssl_command(pt: &PassiveTotal, cmd: &config::SslCmd) -> Result<json::Value> {
    let result = match *cmd {
        config::SslCmd::Certificate { ref query } => pt.ssl().certificate(query).send()?,
        config::SslCmd::History { ref query } => pt.ssl().history(query).send()?,
        config::SslCmd::Search {
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

fn handle_enrichment_command(
    pt: &PassiveTotal,
    cmd: &config::EnrichmentCmd,
) -> Result<json::Value> {
    let result = match *cmd {
        config::EnrichmentCmd::Data { ref query } => pt.enrichment().data(query.clone()).send()?,
        config::EnrichmentCmd::Malware { ref query } => {
            pt.enrichment().malware(query.clone()).send()?
        }
        config::EnrichmentCmd::OsInt { ref query } => pt.enrichment().osint(query.clone()).send()?,
        config::EnrichmentCmd::Subdomains { ref query } => {
            pt.enrichment().subdomains(query.clone()).send()?
        }
    };

    Ok(result)
}

fn handle_actions_command(pt: &PassiveTotal, cmd: &config::ActionCmd) -> Result<json::Value> {
    let result = match *cmd {
        config::ActionCmd::Classification { ref query } => {
            pt.actions().classification(&query).send()?
        }
        config::ActionCmd::Compromised { ref query } => pt.actions().compromised(&query).send()?,
        config::ActionCmd::DynamicDns { ref query } => pt.actions().dynamic_dns(&query).send()?,
        config::ActionCmd::Monitor { ref query } => pt.actions().monitor(&query).send()?,
        config::ActionCmd::Sinkhole { ref query } => pt.actions().sinkhole(&query).send()?,
        config::ActionCmd::Tags { ref query } => pt.actions().tags(&query).send()?,
    };

    Ok(result)
}

fn handle_whois_command(pt: &PassiveTotal, cmd: &config::WhoisCmd) -> Result<json::Value> {
    let result = match *cmd {
        config::WhoisCmd::Search {
            ref field,
            ref query,
        } => if let Some(f) = field.clone() {
            pt.whois().search_field(query, f).send()?
        } else {
            pt.whois().search_keyword(query).send()?
        },
        config::WhoisCmd::Data { ref query } => pt.whois().information(query).send()?,
    };

    Ok(result)
}

fn handle_account_command(pt: &PassiveTotal, cmd: &config::AccountCmd) -> Result<json::Value> {
    let result = match *cmd {
        config::AccountCmd::Info => pt.account().info().send()?,
        config::AccountCmd::History => pt.account().history().send()?,
        config::AccountCmd::Monitors => pt.account().monitors().send()?,
        config::AccountCmd::Organization => pt.account().organization().send()?,
        config::AccountCmd::Quotas => pt.account().quota().send()?,
        config::AccountCmd::Sources { ref source } => {
            pt.account().sources().source(source.clone()).send()?
        }
        config::AccountCmd::Teamstream => pt.account().organization().teamstream().send()?,
    };

    Ok(result)
}

fn run(pt: &PassiveTotal, args: &Opt) -> Result<()> {
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

    Ok(match args.output {
        Some(ref path) => {
            let f = File::create(path)?;
            print_response(f, &resp, args.pretty)?
        }
        _ => print_response(std::io::stdout(), &resp, args.pretty)?,
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
    let opt = Opt::from_args();

    let config = match Config::from_opt(&opt) {
        Ok(cfg) => cfg,
        Err(ref e) => {
            print_errors(e);
            return;
        }
    };

    let pt = PassiveTotal::new(
        config.passivetotal.username,
        config.passivetotal.apikey,
        Duration::from_secs(opt.timeout),
    );

    if let Err(ref e) = run(&pt, &opt) {
        print_errors(e);
    }
}
