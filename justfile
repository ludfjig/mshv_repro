guest:
    cd crates/guest && cargo +nightly build

run: guest
    cargo run

@offset:
    objdump -d crates/guest/target/debug/guest | grep _start -m 1 | awk '{printf "0x%x\n", strtonum("0x"$1)}'