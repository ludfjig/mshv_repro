#![no_std]
#![no_main]

use core::arch::asm;

#[no_mangle]
pub unsafe extern "C" fn _start(_output_ptr: u64) -> ! {
    // let output_ptr = output_ptr as *mut u64;
    // result will be in rax
    // out(5, 4);
    let _res = fib(13);
    // output_ptr.write(res);
    asm!("hlt");
    unreachable!()
}

// prevent inlining
#[no_mangle]
#[inline(never)]
fn fib(i: u64) -> u64 {
    match i {
        0 => 0,
        1 => 1,
        _ => fib(i - 1) + fib(i - 2),
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    out(5, 5); // some random nums to detect panic
    loop {}
}

// writes value to port
fn out(port: u16, value: u16) {
    unsafe {
        asm!(
            "out dx, ax",
            in("dx") port,
            in("ax") value,
            options(nomem, nostack, preserves_flags)
        );
    }
}
