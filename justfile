guest:
    cd crates/guest && cargo +nightly build

run: guest
    cargo run
