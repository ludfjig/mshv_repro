On a machine with `/dev/mshv` do the following:

1. Run `(cd crates/guest && cargo +nightly build)` in root of repo to build guest binary. This requires nightly rust toolchain (`rustup toolchain install nightly`). You might need to install the windows target on the nightly toolchain (`rustup +nightly target add x86_64-pc-windows-msvc`).

2. Run the host program with `cargo run` from the repo root. The program should run successfully.

3. Run the host program with `cargo run --features bug` from the repo root. The program should now fail an assertion.

The only difference between the two runs is that in the second one, the bitmap is saved onto a vec. I'm stumped why or how this somehow can influce what bitmaps are returned.