# Using Concrete-core from Javascript

This crate exposes an experimental Javascript interface to the `concrete-core` library. Using this API, it is possible to execute FHE operations in the browser, for instance.

## Building `concrete-core-wasm` for `nodejs`

To build `concrete-core-wasm`, you will not only need Rust to be installed, but also a named `wasm-pack`. This tool will not only call the rust compiler to generate the `wasm` code, but will also generate a Javascript boilerplate to ease the integration with your use case (be it `nodejs` or for the browser).

To install `wasm-pack` see [the project homepage](https://rustwasm.github.io/wasm-pack/installer/).

Then you can use `wasm-pack` to compile the `concrete-core-wasm` API with:

```shell
wasm-pack build --target nodejs
```
