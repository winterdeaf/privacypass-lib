# Kagi Privacy Pass Core Library

This repository contains the source code of the core library implementing the Privacy Pass API used by [Kagi](https://blog.kagi.com/kagi-privacy-pass).
This repository is not meant to be used as stand-alone, but rather as a submodule for other projects.

## Disclaimers about this fork

This is an LLM-assisted port of the privacy pass core library, with the following two goals:

1. Update the rust toolchain from v1.84 to v1.94;
2. Update the dependencies: switch to current versions of [privacypass](https://github.com/raphaelrobert/privacypass), [voprf](https://github.com/facebook/voprf) and [blind-rsa-signatures](https://github.com/jedisct1/rust-blind-rsa-signatures).

This required some hacks (mostly in the form of privacypass patches) in order to maintain wire format compatibility with the Kagi servers.
**Note that neither this fork, nor [privacypass](https://github.com/raphaelrobert/privacypass)have been audited, and I did not review all of the LLM-edited changes in detail.**


## Building using Docker

To build this library, install Docker and run
```bash
bash build.sh
```
If using Podman, run
```bash
DOCKER=podman bash build.sh
```
The output library will be found in `/build`.

## Building on host machine

### Installing the build dependencies

To build this project directly on your host machine, you need [rust](https://www.rust-lang.org/) and [wasm-pack](https://rustwasm.github.io/wasm-pack/).

You can obtain Rust by using [rustup](https://rustup.rs/), and wasm-pack by using its [installer](https://rustwasm.github.io/wasm-pack/installer/).

### Building the library

Once the above dependencies were obtained, run
```bash
cd src
bash build.sh
```
The output library will be found in `/src/wasm/pkg`.
