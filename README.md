# Build the guest binary and get binary entrypoint offset

`cd crates/guest && cargo build && objdump -d target/debug/guest | grep _start -m 1 | awk '{printf "0x%x\n", strtonum("0x"$1)}'`
and note the output