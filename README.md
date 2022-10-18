<p align="center">
<!-- product name logo -->
  <img width=600 src="https://user-images.githubusercontent.com/5758427/196391638-ebade124-1123-4d8a-b46d-bfbe1c943f9c.png">
</p>
<p align="center">
<!-- Version badge using shields.io -->
  <a href="https://github.com/zama-ai/concrete-core/releases">
    <img src="https://img.shields.io/github/v/release/zama-ai/concrete-core?style=flat-square">
  </a>
<!-- Link to docs badge using shields.io -->
  <a href="https://docs.zama.ai/concrete-core">
    <img src="https://img.shields.io/badge/read-documentation-yellow?style=flat-square">
  </a>
<!-- Link to tutorials badge using shields.io -->
  <a href="https://docs.zama.ai/concrete-core/adding-a-new-backend/creating_backends">
    <img src="https://img.shields.io/badge/tutorials-and%20demos-orange?style=flat-square">
  </a>
<!-- Community forum badge using shields.io -->
  <a href="https://community.zama.ai">
    <img src="https://img.shields.io/badge/community%20forum-online-brightgreen?style=flat-square">
  </a>
<!-- Open source badge using shields.io -->
  <a href="https://github.com/zama-ai/concrete-core/edit/main/README.md#contributing">
    <img src="https://img.shields.io/badge/we're%20open%20source-contributing.md-blue?style=flat-square">
  </a>
<!-- Follow on twitter badge using shields.io -->
  <a href="https://twitter.com/zama_fhe">
    <img src="https://img.shields.io/twitter/follow/zama_fhe?color=blue&style=flat-square">
  </a>
</p>

The `Concrete-core` library is a crate that implements Zama's variant of
[TFHE](https://eprint.iacr.org/2018/421.pdf). In a nutshell,
[fully homomorphic encryption (FHE)](https://en.wikipedia.org/wiki/Homomorphic_encryption), allows
you to perform computations over encrypted data, allowing you to implement Zero Trust services.

Concrete-core is based on the
[Learning With Errors (LWE)](https://cims.nyu.edu/~regev/papers/lwesurvey.pdf) and the
[Ring Learning With Errors (RLWE)](https://eprint.iacr.org/2012/230.pdf) problems, which are well
studied cryptographic hardness assumptions believed to be secure even against quantum computers.

## Links

- [Documentation](https://docs.zama.ai/concrete-core)
- [Whitepaper](https://whitepaper.zama.ai)
- [Community website](https://community.zama.ai)

## Concrete-core crates

Concrete-core is implemented using the [Rust Programming language](https://www.rust-lang.org/), which
enables very fast, yet very secure implementations.

The library is composed of several crates (packages in the Rust language):

+ [`Concrete-core`](concrete-core): A Rust implementation of FHE, useful to cryptographers who want the
  fastest implementation possible, with all the settings at their disposal.
+ [`Concrete-core-ffi`](concrete-core-ffi): A prototype of C API for `Concrete-core`
+ [`Concrete-core-wasm`](concrete-core-wasm): A Javascript API for `Concrete-core`
+ [`Concrete-cuda`](concrete-cuda): A Cuda acceleration of a subset of operations supported in `Concrete-core`
+ [`Concrete-npe`](concrete-npe): A noise propagation estimator, used in `concrete` to simulate the
  evolution of the noise in ciphertexts, through homomorphic operations.
+ [`Concrete-csprng`](concrete-csprng): A fast cryptographically secure pseudorandom number
  generator used in `concrete-core`.
+ [`Concrete-core-fixture`](concrete-core-fixture): A tool for sampling, testing and benchmarking `Concrete-core`
+ [`Concrete-core-test`](concrete-core-test): The instantiation of all tests for `Concrete-core`
+ [`Concrete-core-bench`](concrete-core-bench): The instantiation of all benchmarks for `Concrete-core`

## Installation

To use `Concrete-core`, you will need the following things:
- A Rust compiler
- A C compiler & linker
- make

The Rust compiler can be installed on __Linux__ and __macOS__ with the following command:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

You can also check [https://rustup.rs/](https://rustup.rs/) for specific installation methods for your system.

All installation methods are listed on the
[rust website](https://forge.rust-lang.org/infra/other-installation-methods.html).

### macOS

To have the required C compiler and linker you'll either need to install the full __XCode__ IDE
(that you can install from the AppleStore) or install the __Xcode Command Line Tools__ by typing the
following command:

```bash
xcode-select --install
```

### Linux

On linux, installing the required components depends on your distribution.
But for the typical Debian-based/Ubuntu-based distributions,
running the following command will install the needed packages:
```bash
sudo apt install build-essential
```

### Windows

Concrete-core comes with an experimental Windows support for a subset of implementations.
It is experimental since Windows platforms are not integrated in the continuous integration as of now.
Command to build for Windows:
```
RUSTFLAGS="-Ctarget-cpu=native" cargo build --no-default-features --features="backend_default,backend_default_parallel,backend_default_generator_x86_64_aesni,backend_default_serialization,backend_fft,backend_fft_serialization,seeder_x86_64_rdseed" --release -p concrete-core
```

### x86_64 platforms

Command to build on x86_64 platforms:
```
RUSTFLAGS="-Ctarget-cpu=native" cargo build --features="x86_64" --release -p concrete-core
```

### Apple Silicon platforms

Apple Silicon support is still experimental in the library, as we need to strengthen continuous integration for this platform. 
Command to build on Apple Silicon platforms:
```
RUSTFLAGS="-Ctarget-cpu=native" cargo +nightly build --features="aarch64" --release -p concrete-core
```
Beware that you have to use the nightly toolchain for Apple Silicon support.

## Contributing

There are two ways to contribute to Concrete-core:

- you can open issues to report bugs or typos and to suggest new ideas
- you can ask to become an official contributor by emailing [hello@zama.ai](mailto:hello@zama.ai).
(becoming an approved contributor involves signing our Contributor License Agreement (CLA))

Only approved contributors can send pull requests, so please make sure to get in touch before you do!

## Need support?

<a target="_blank" href="https://community.zama.ai">
  <img src="https://user-images.githubusercontent.com/5758427/191792238-b132e413-05f9-4fee-bee3-1371f3d81c28.png">
</a>

## Citing Concrete-core

To cite Concrete-core in academic papers, please use the following entry:

```
@inproceedings{WAHC:CJLOT20,
  title={CONCRETE: Concrete Operates oN Ciphertexts Rapidly by Extending TfhE},
  author={Chillotti, Ilaria and Joye, Marc and Ligier, Damien and Orfila, Jean-Baptiste and Tap, Samuel},
  booktitle={WAHC 2020--8th Workshop on Encrypted Computing \& Applied Homomorphic Cryptography},
  volume={15},
  year={2020}
}
```

## Credits

This library uses several dependencies and we would like to thank the contributors of those
libraries.

We thank [Daniel May](https://gitlab.com/danieljrmay) for supporting this project and donating the
`concrete` crate.

## License

This software is distributed under the BSD-3-Clause-Clear license. If you have any questions,
please contact us at `hello@zama.ai`.

## Disclaimers

### Security Estimation

Security estimation, in this repository, used to be based on
the [LWE Estimator](https://bitbucket.org/malb/lwe-estimator/src/master/),
with `reduction_cost_model = BKZ.sieve`.
We are currently moving to the [Lattice Estimator](https://github.com/malb/lattice-estimator)
with `red_cost_model = reduction.RC.BDGL16`.

When a new update is published in the Lattice Estimator, we update parameters accordingly.

### Side-Channel Attacks

Mitigation for side channel attacks have not yet been implemented in Concrete,
and will be released in upcoming versions.
