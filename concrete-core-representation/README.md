# Concrete Core Representation

This library contains tools to perform source-code analysis on the `concrete-core` repository.

## Output a human readable summary of the local sources

You can output a human readable summary of the local sources with the following command:
```shell
cargo run --release -p concrete-core-representation --bin summary
```

## Dump the representation of the local repository

Alternatively, for a finer grained picture of the source code (and for debugging), you can dump a 
json representation of the sources in `/tmp/ccr_dump.json`
```shell
cargo run --release -p concrete-core-representation --bin dump
```

Firefox has a nice built-in json viewer:
```shell
firefox /tmp/ccr_dump.json
```

## License

This software is distributed under the BSD-3-Clause-Clear license. If you have any questions,
please contact us at `hello@zama.ai`.
