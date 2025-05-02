use std::thread;
use std::time::Duration;

mod kvm;
mod mshv;
mod shared;

use kvm::setup_initial_sregs_kvm;
use libc::mmap;

use mshv::setup_initial_sregs_mshv;
use mshv_bindings::{HV_MAP_GPA_EXECUTABLE, HV_MAP_GPA_READABLE, HV_MAP_GPA_WRITABLE};
use shared::{Registers, Vm};
use x86::bits64::paging::{PAddr, PDEntry, PDFlags, PDPTEntry, PDPTFlags, PML4Entry, PML4Flags};

const PAGE_SHIFT: usize = 12;
const PAGE_SIZE: usize = 1 << PAGE_SHIFT; // 4KB

const GUEST_PHYSICAL_ADDR_BASE: usize = 0x200000;
const GUEST_PFN_BASE: usize = GUEST_PHYSICAL_ADDR_BASE >> PAGE_SHIFT;

const CODE_OFFSET: usize = 0x3000;

const EFER_LME: u64 = 1 << 8;
const EFER_LMA: u64 = 1 << 10;

fn main() {
    let memory_size = 5 * 1024 * 1024; // 5MB

    // setup memory
    let memory_arena_raw = setup_memory_arena(memory_size);
    setup_page_tables(memory_arena_raw as *mut u64);

    // Uncomment for KVM instead of MSHV

    // let mut vm = kvm::create_vm();
    // setup_initial_sregs_kvm(&mut vm);
    // vm.map_memory_kvm(kvm_bindings::kvm_userspace_memory_region {
    //     slot: 0,
    //     flags: 0,
    //     guest_phys_addr: 0x200_000,
    //     memory_size: memory_size as u64,
    //     userspace_addr: memory_arena_raw as u64,
    // });
    let mut vm = mshv::create_vm();
    setup_initial_sregs_mshv(&mut vm);
    vm.map_memory_mshv(mshv_bindings::mshv_user_mem_region {
        size: memory_size as u64,
        guest_pfn: GUEST_PFN_BASE as u64,
        userspace_addr: memory_arena_raw as u64,
        flags: HV_MAP_GPA_READABLE | HV_MAP_GPA_WRITABLE | HV_MAP_GPA_EXECUTABLE,
    });

    run_guest_entrypoint(&mut vm, memory_arena_raw, memory_size);

    extern "C" fn handle_sigusr1(_: libc::c_int) {
        // do nothing. Default is to kill the process
    }
    unsafe {
        libc::signal(libc::SIGUSR1, handle_sigusr1 as usize);
    }
    let interrupt_handle = vm.interrupt_handle();

    // Kill the blocking vm after 3 secs
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(3));
        interrupt_handle.interrupt_vm_if_running();
    });

    // runs forever
    println!("Entering infinite loop in guest...");
    vm.run_until_halt_or_err();

    println!("Execution continued after guest infinite loop");
}

fn setup_memory_arena(memory_size: usize) -> *mut u8 {
    unsafe {
        mmap(
            std::ptr::null_mut(),
            memory_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
            -1,
            0,
        ) as *mut u8
        // let layout = Layout::from_size_align(memory_size, PAGE_SIZE).unwrap();
        // std::alloc::alloc_zeroed(layout) as *mut u8
    }
}

fn setup_page_tables(memory_arena: *mut u64) {
    // Physical Guest Memory layout:
    // -----------------
    // 0x0000000 - 0x20_0000: Unmapped
    // 0x20_0000 - 0x20_1000 PDL4 table with only 1 entry
    // 0x20_1000 - 0x20_2000 PDPT table with only 1 entry
    // 0x20_2000 - 0x20_3000 PD table with 512 entries
    // 0x20_3000 - Code

    let pdl4_guest_paddr = PAddr::from(GUEST_PHYSICAL_ADDR_BASE);
    let pdpt_addr = pdl4_guest_paddr + PAddr::from(0x1000);
    let pd_addr = pdl4_guest_paddr + PAddr::from(0x2000);

    // Create PML4 table with only 1 PML4 entry
    let pml4e = PML4Entry::new(pdpt_addr, PML4Flags::P | PML4Flags::RW);
    unsafe { memory_arena.write(pml4e.0) };

    // Create PDPT with only 1 PDPT entry
    let pdpte = PDPTEntry::new(pd_addr, PDPTFlags::P | PDPTFlags::RW);
    unsafe { memory_arena.byte_add(0x1000).write(pdpte.0) };

    // Create 1 PD table with only 512 PD entries
    for i in 0..512 {
        let pde = PDEntry::new(PAddr::from(i << 21), PDFlags::P | PDFlags::RW | PDFlags::PS); // 2 MB pages
        unsafe { memory_arena.byte_add(0x2000 + i * 8).write(pde.0) };
    }
}

fn get_guest_binary_entrypoint_offset(code: &[u8]) -> usize {
    let elf = goblin::elf::Elf::parse(code).unwrap();
    let entry = elf.entry;
    let offset = elf
        .program_headers
        .iter()
        .find(|ph| ph.p_vaddr <= entry && entry < ph.p_vaddr + ph.p_memsz)
        .map(|ph| entry - ph.p_vaddr + ph.p_offset)
        .unwrap();
    offset as usize
}

fn run_guest_entrypoint(vm: &mut impl Vm, memory_arena_raw: *mut u8, memory_size: usize) {
    // write guest binary to memory
    let code = include_bytes!("../../guest/target/x86_64-unknown-none/debug/guest");
    let entrypoint_offset = get_guest_binary_entrypoint_offset(code);
    unsafe {
        std::ptr::copy(
            code.as_ptr(),
            memory_arena_raw.byte_add(CODE_OFFSET),
            code.len(),
        );
    }
    let output_offset = (CODE_OFFSET + code.len()).next_multiple_of(PAGE_SIZE);

    // Run entrypoint fn in guest
    let regs = Registers {
        rip: (GUEST_PHYSICAL_ADDR_BASE + CODE_OFFSET + entrypoint_offset) as u64,
        rsp: (GUEST_PHYSICAL_ADDR_BASE + memory_size - 0x28) as u64,
        rdi: (GUEST_PHYSICAL_ADDR_BASE + output_offset) as u64, // first parameter output buffer
        rflags: 0x2,
        ..Default::default()
    };
    vm.set_regs(&regs);
    vm.run_until_halt_or_err();

    // get result from entrypoint fn (written to output buffer)
    let dispatch_fn_addr = unsafe { (memory_arena_raw.byte_add(output_offset) as *mut u64).read() };

    // set regs
    let mut regs = vm.regs();
    regs.rip = dispatch_fn_addr;
    regs.rsp = (GUEST_PHYSICAL_ADDR_BASE + memory_size - 0x28) as u64;
    regs.rflags = 0x2;
    vm.set_regs(&regs);
}
