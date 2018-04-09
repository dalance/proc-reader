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
proc-reader = "0.1.2"
```

## Example

```rust
extern crate nix;
extern crate proc_reader;
use nix::unistd::Pid;
use proc_reader::ProcReader;
use std::process::Command;
use std::io::{BufReader, Read};
use std::time::Duration;
use std::thread;

fn main() {
    // Create a process for reading stdout
    let mut child = Command::new("sh").arg("-c").arg("sleep 1; echo aaa").spawn().unwrap();

    // Create `ProcReader` from pid
    let pid = Pid::from_raw(child.id() as i32);
    let reader = ProcReader::from_stdout(pid);
    let mut reader = BufReader::new(reader);

    // Wait the end of process
    thread::sleep(Duration::from_secs(2));

    // Read from `ProcReader`
    let mut line = String::new();
    let _ = reader.read_to_string(&mut line);
    assert_eq!( "aaa\n", line);
}
```
