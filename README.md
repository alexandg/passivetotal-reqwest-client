`passivetotal-client`
-------------------------

A [`reqwest`](https://github.com/seanmonstar/reqwest)-based Rust CLI client for
querying the [PassiveTotal](https://www.passivetotal.org)
[API](https://api.passivetotal.org/api/docs/) using the
[`passivetotal-reqwest`](https://github.com/alexandg/passivetotal-reqwest)
crate.

Requires Rust v1.19+.

### Install and build

To use this crate clone this repo and the build it with `cargo`

```
git clone https://github.com/alexandg/passivetotal-client.git
cd passivetotal-client
cargo build --release
```

### Configuration

This crate requires a valid PassiveTotal API username and key. These can be
provided to the command line app by storing them in a toml configuration file
with the following format:

```toml
[passivetotal]
username = "USERNAME"
apikey = "API_KEY"
timeout = 60
```

This file can either be provided on the command line with the `--config` flag
or placed in `$HOME/.passivetotal.toml`.

### Examples

Assuming you have the compiled binary in your `$PATH`

#### Simple Query

```
passivetotal-client pdns "passivetotal.org"
```

#### Pretty printing results

```
passivetotal-client --pretty pdns "passivetotal.org"
```

#### Writing a pretty printed response to a file

```
passivetotal-client --pretty -o <PATH TO FILE> pdns "passivetotal.org"
```

For a full list of available options and subcommands run

```
passivetotal-client --help
```

For more information about the options available for a specific subcommand
run

```
passivetotal-client <COMMAND> --help
```

### License

`passivetotal-client` is licensed under the MIT License.
