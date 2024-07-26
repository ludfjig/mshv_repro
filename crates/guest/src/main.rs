#![no_std]
#![no_main]

use core::arch::asm;

#[no_mangle]
pub unsafe extern "C" fn entrypoint(output_ptr: u64) -> ! {
    let output_ptr = output_ptr as *mut u64;
    output_ptr.write(dispatch_function as u64);
    asm!("hlt");
    unreachable!()
}

#[no_mangle]
pub unsafe extern "C" fn dispatch_function() -> ! {
    let _dirty = 11; // the stack will be dirtied because this value will be written to stack (in debug mode). It is optimized away in release mode
    asm!("hlt");
    unreachable!()
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    out(5, 2147000000); // a random num to detect panic
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

// Unresolved symbols
#[no_mangle]
pub(crate) extern "C" fn __CxxFrameHandler3() {}
#[no_mangle]
pub(crate) static _fltused: i32 = 0;
