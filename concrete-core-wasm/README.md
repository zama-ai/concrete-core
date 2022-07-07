# Concrete-Core Wasm Interface

This crate exposes an experimental Wasm interface to the `concrete-core` library. Using this api, 
it is possible to execute FHE operations in the browser for instance.

This API is currently experimental and therefore unstable in terms of naming and exposed 
structures/entry points.

## An example

### Building `concrete-core-wasm` for `nodejs`.

To build `concrete-core-wasm`, you will not only need `rust` to be installed, but also a named
`wasm-pack`. This tool will not only call the rust compiler to generate the `wasm` code, but will 
also generate a javascript boilerplate to ease the integration with your usecase (be it `nodejs`,
or for the browser).

To install `wasm-pack` see [the project homepage](https://rustwasm.github.io/wasm-pack/installer/).

Then you can use `wasm-pack` to compile the `concrete-core-wasm` api with:
```shell
wasm-pack build --target nodejs
```

## Links

- [TFHE](https://eprint.iacr.org/2018/421.pdf)
- [Concrete-core user documentation](https://docs.zama.ai/concrete-core)
- [Concrete-core V1.0.0-alpha release](https://community.zama.ai/t/concrete-core-v1-0-0-alpha/120)
- [Concrete-core V1.0.0-beta release](https://www.zama.ai/post/announcing-concrete-core-v1-0-beta)
- [Concrete-core V1.0.0-gamma release](https://community.zama.ai/t/concrete-core-v1-0-0-gamma-with-gpu-acceleration/234)

## License

This software is distributed under the BSD-3-Clause-Clear license. If you have any questions,
please contact us at `hello@zama.ai`.
