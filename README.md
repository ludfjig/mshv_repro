On a machine with `/dev/mshv` do the following:

1. Run `(cd crates/guest && cargo +nightly build)` in root of repo to build guest binary. You might need to install the windows target to build the guest binary: `rustup target add x86_64-pc-windows-msvc`. And you need the nightly rust toolchain as well.

2. Run the host program with `cargo run` from the repo root. The program should run successfully.

3. Run the host program with `cargo run --features bug` from the repo root. The program should now fail an assertion.

The only difference between the two runs is that in the second one, the bitmap is saved onto a vec. I'm stumped why or how this somehow can influce what bitmaps are returned.