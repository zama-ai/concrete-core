# Concrete Core Tests

This library contains statistical tests for the `concrete-core` library.

To execute the tests for the default backend:
```shell
RUSTFLAGS="-Ctarget-cpu=native" cargo test --release --features=backend_default -- some_filters
```

You can check the [Cargo.toml](./Cargo.toml) for more features to enable for testing different parts of `concrete-core`.

## License

This software is distributed under the BSD-3-Clause-Clear license. If you have any questions,
please contact us at `hello@zama.ai`.
