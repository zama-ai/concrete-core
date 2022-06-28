# Concrete-Core Wasm Interface

This crate exposes an experimental Wasm interface to the `concrete-core` library. Using this api, 
it is possible to execute FHE operations in the browser for instance.

This API is currently experimental and therefore unstable in terms of naming and exposed 
structures/entry points.

## An example

### Building `concrete-core-wasm` for `nodejs`.

```shell
wasm-pack build --target nodejs
```

## Links

- [TFHE](https://eprint.iacr.org/2018/421.pdf)
- [concrete-core-1.0.0-alpha release](https://community.zama.ai/t/concrete-core-v1-0-0-alpha/120)

## License

This software is distributed under the BSD-3-Clause-Clear license. If you have any questions,
please contact us at `hello@zama.ai`.
