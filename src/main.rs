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
extern crate passivetotal_client as client;
extern crate passivetotal_reqwest as passivetotal;
extern crate structopt;

use std::time::Duration;

use passivetotal::PassiveTotal;
use structopt::StructOpt;

use client::config::Config;
use client::opt::Opt;

fn main() {
    let opt = Opt::from_args();

    let config = match Config::from_opt(&opt) {
        Ok(cfg) => cfg,
        Err(ref e) => {
            client::print_errors(e);
            return;
        }
    };

    let pt = PassiveTotal::new(
        config.passivetotal.username,
        config.passivetotal.apikey,
        Duration::from_secs(opt.timeout),
    );

    if let Err(ref e) = client::run(&pt, &opt) {
        client::print_errors(e);
    }
}
