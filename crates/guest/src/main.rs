#![no_std]
#![no_main]

use core::arch::asm;

#[no_mangle]
pub unsafe extern "C" fn entrypoint(output_ptr: *mut u64) -> ! {
    output_ptr.write(dispatch_function as u64);
    asm!("hlt");
    unreachable!()
}

#[no_mangle]
pub unsafe extern "C" fn dispatch_function() -> ! {
    let res = fib(10);
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
    out(5, 2147000000); // some random nums to detect panic
    loop {}
}

// writes value to port
fn out(port: u16, value: u32) {
    unsafe {
        asm!(
            "out dx, eax",
            in("dx") port,
            in("eax") value,
            options(nomem, nostack, preserves_flags)
        );
    }
}

#[no_mangle]
pub extern "C" fn __CxxFrameHandler3() {}

#[no_mangle]
pub extern "C" fn _fltused() {}
