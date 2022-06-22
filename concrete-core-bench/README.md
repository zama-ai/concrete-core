# Concrete Core Benchmarks

This library contains benchmarking facilities for the `concrete-core` library.

To execute the benchmarks for the default backend:
```shell
RUSTFLAGS="-Ctarget-cpu=native" cargo run --release --features=backend_default -- --bench
```

Note that you have to activate the feature flags corresponding to the backends you want to benchmark with the 
`--features=...` command line argument.

You can check the [Cargo.toml](./Cargo.toml) for more features to enable for benchmarking different parts of `concrete-core`.

## License

This software is distributed under the BSD-3-Clause-Clear license. If you have any questions,
please contact us at `hello@zama.ai`.
