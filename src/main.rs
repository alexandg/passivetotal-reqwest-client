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

    let timeout = config.timeout.unwrap_or(opt.timeout);
    let pt = PassiveTotal::new(config.username, config.apikey, Duration::from_secs(timeout));

    if let Err(ref e) = client::run(&pt, &opt) {
        client::print_errors(e);
    }
}
