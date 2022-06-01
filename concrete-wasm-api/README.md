# Wasm client 

This repo purpose is to build a wasm package to expose concrete core methods into the browser. 

## Build a wasm package 

The following build operation has been done on x86 using Fedora.
To build the package we need to install wasm-pack utility.

### Install wasm-pack

Unfortunately the last version 0.10.x was not working because of a curl or openssl issue. 
Instead install the 0.9.1 solved the issue. 
```bash
cargo install wasm-pack --version 0.9.1
```
See [here](https://github.com/rustwasm/wasm-pack/issues/823#issuecomment-978162652)

### Build 

For web:

```bash
wasm-pack  build --target web
```

For nodejs:

```bash
wasm-pack  build --target nodejs
```


This will create a pkg folder, the most useful part for us is the __concrete_wasm_api.js__ file. 

### Last step before use

This will be modified in the future.

Add this line to the end of concrete_wasm_api.js :

```bash
echo 'window.FHEinit = init;' >> pkg/concrete_wasm_api.js
```

## Use wasm package

The following repo explains how to use the built package. 
TODO : add link to web-sdk repo.