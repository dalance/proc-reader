# proc-reader

[![Build Status](https://travis-ci.org/dalance/proc-reader.svg?branch=master)](https://travis-ci.org/dalance/proc-reader)
[![Crates.io](https://img.shields.io/crates/v/proc-reader.svg)](https://crates.io/crates/proc-reader)
[![Docs.rs](https://docs.rs/proc-reader/badge.svg)](https://docs.rs/proc-reader)
[![codecov](https://codecov.io/gh/dalance/proc-reader/branch/master/graph/badge.svg)](https://codecov.io/gh/dalance/proc-reader)

A std::io::Read implementation for stdout/stderr of other process

[Documentation](https://docs.rs/proc-reader)

## Usage

```Cargo.toml
[dependencies]
proc-reader = "0.5.1"
```

## Supported Platform

- x86_64-unknown-linux-gnu
- x86_64-unknown-linux-musl
- i686-unknown-linux-gnu
- i686-unknown-linux-musl

## Example

```rust
extern crate proc_reader;
use proc_reader::ProcReader;
use std::process::Command;
use std::io::Read;
use std::time::Duration;
use std::thread;

fn main() {
    // Create a process for reading stdout
    let child = Command::new("sh").arg("-c").arg("sleep 1; echo aaa").spawn().unwrap();

    // Create ProcReader from pid
    let mut reader = ProcReader::from_stdout(child.id());

    // Wait the end of process
    thread::sleep(Duration::from_secs(2));

    // Read from ProcReader
    let mut line = String::new();
    let _ = reader.read_to_string(&mut line);
    assert_eq!( "aaa\n", line);
}
```
