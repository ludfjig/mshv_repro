use std::process::Command;

use libc::{memrchr, mmap, munmap};
use mshv_bindings::{
    hv_message, hv_message_type_HVMSG_UNMAPPED_GPA, hv_message_type_HVMSG_UNRECOVERABLE_EXCEPTION,
    hv_message_type_HVMSG_X64_HALT, hv_message_type_HVMSG_X64_IO_PORT_INTERCEPT,
    mshv_user_mem_region, HV_MAP_GPA_EXECUTABLE, HV_MAP_GPA_READABLE, HV_MAP_GPA_WRITABLE,
};
use mshv_ioctls::{Mshv, VcpuFd, VmFd};
use x86::bits64::paging::{PAddr, PDEntry, PDFlags, PDPTEntry, PDPTFlags, PML4Entry, PML4Flags};
use x86::controlregs::Cr0;
use x86::controlregs::Cr4;

const PAGE_SHIFT: usize = 12;
const PAGE_SIZE: usize = 1 << PAGE_SHIFT; // 4KB

const GUEST_PHYSICAL_ADDR_BASE: usize = 0x200000;
const GUEST_PFN_BASE: usize = GUEST_PHYSICAL_ADDR_BASE >> PAGE_SHIFT;

const CODE_OFFSET: usize = 0x3000;

const EFER_LME: u64 = 1 << 8;
const EFER_LMA: u64 = 1 << 10;

fn main() {
    let mut failures = vec![];
    // RUN
    for memory_size in (550 * PAGE_SIZE..850 * PAGE_SIZE).step_by(PAGE_SIZE) {
        // setup memory
        let memory_arena_raw = setup_memory_arena(memory_size);
        let memory_arena = unsafe { std::slice::from_raw_parts_mut(memory_arena_raw, memory_size) };
        setup_page_tables(memory_arena);

        // create vm and vcpu
        let (vm, mut vcpu) = create_vm();
        setup_initial_sregs(&mut vcpu);

        // map memory into vm
        vm.map_user_memory(mshv_user_mem_region {
            guest_pfn: GUEST_PFN_BASE as u64,
            size: memory_size as u64,
            userspace_addr: memory_arena.as_ptr() as u64,
            flags: HV_MAP_GPA_READABLE | HV_MAP_GPA_WRITABLE | HV_MAP_GPA_EXECUTABLE,
        })
        .unwrap();

        // write binary code to memory
        // let code = include_bytes!("../../guest/target/debug/guest");
        let code = include_bytes!("../../guest/target/x86_64-pc-windows-msvc/debug/guest.exe");
        let entrypoint_offset = get_guest_binary_entrypoint_offset(code);
        memory_arena[CODE_OFFSET..CODE_OFFSET + code.len()].copy_from_slice(code);
        let output_offset = (CODE_OFFSET + code.len()).next_multiple_of(PAGE_SIZE);

        // Run entrypoint fn in guest
        let mut regs = vcpu.get_regs().unwrap();
        regs.rip = (GUEST_PHYSICAL_ADDR_BASE + CODE_OFFSET + entrypoint_offset) as u64;
        regs.rsp = (GUEST_PHYSICAL_ADDR_BASE + memory_size - 0x28) as u64;
        regs.rcx = (GUEST_PHYSICAL_ADDR_BASE + output_offset) as u64; // first parameter output buffer
        regs.rflags = 0x2;
        vcpu.set_regs(&regs).unwrap();
        drop(memory_arena);
        execute_until_halt(&mut vcpu);
        get_and_clear_dirty_pages(memory_size, &vm);

        // get result from entrypoint fn (written to output buffer)
        let dispatch_fn_addr = unsafe { (memory_arena_raw.add(output_offset) as *mut u64).read() };

        // Run the `dispatch_function` couple of times
        for i in 0..1000 {
            let mut regs = vcpu.get_regs().unwrap();
            regs.rip = dispatch_fn_addr;
            regs.rsp = (GUEST_PHYSICAL_ADDR_BASE + memory_size - 0x28) as u64;
            regs.rflags = 0x2;
            vcpu.set_regs(&regs).unwrap();
            execute_until_halt(&mut vcpu);

            let pages = get_and_clear_dirty_pages(memory_size, &vm);
            let last_page_idx = memory_size / PAGE_SIZE - 1;
            let last_block_idx = last_page_idx / 64;
            let last_page_bit_idx = last_page_idx % 64;

            let num_dirty_pages = pages.iter().map(|block| block.count_ones()).sum::<u32>();
            print!(
                "\rMemory size: {:#x}, dirty pages: {}",
                memory_size, num_dirty_pages
            );
            assert_eq!(num_dirty_pages, 4);

            let top_of_stack_dirty = pages[last_block_idx] & (1 << last_page_bit_idx) != 0;
            if !top_of_stack_dirty {
                failures.push((memory_size, i));
            }

            // restore memory
            // unsafe { core::ptr::copy(base_snapshot.as_ptr(), memory_arena_raw, memory_size) };
        }
        unsafe { munmap(memory_arena_raw as *mut libc::c_void, memory_size) };
        println!();
    }
    for (memory_size, i) in &failures {
        println!(
            "Stack not marked dirty for memory size: {:#x} ({} pages), iteration: {}",
            memory_size,
            memory_size / PAGE_SIZE,
            i
        );
    }
    assert!(failures.is_empty())
}

#[allow(non_upper_case_globals)]
fn execute_until_halt(vcpu: &mut VcpuFd) {
    // Run CPU until halt
    loop {
        let hv_message: hv_message = unsafe { std::mem::zeroed() };
        match vcpu.run(hv_message) {
            Ok(m) => match m.header.message_type {
                hv_message_type_HVMSG_X64_HALT => {
                    // println!("Vcpu halted");
                    break;
                }
                hv_message_type_HVMSG_X64_IO_PORT_INTERCEPT => {
                    let io = m.to_ioport_info().unwrap();
                    let port = io.port_number;
                    let val = io.rax;
                    let mut regs = vcpu.get_regs().unwrap();
                    regs.rip += 1;
                    vcpu.set_regs(&regs).unwrap();
                    println!("io port intercept on port {}, with value: {}", port, val);
                }
                hv_message_type_HVMSG_UNMAPPED_GPA => {
                    let mimo_message = m.to_memory_info().unwrap();
                    let paddr = mimo_message.guest_physical_address;
                    let vaddr = mimo_message.guest_virtual_address;
                    let rip = mimo_message.header.rip;
                    println!(
                        "Unmapped gpa! paddr: {:#x} vaddr: {:#x}, rip: {:#x}",
                        paddr, vaddr, rip
                    );
                    break;
                }
                hv_message_type_HVMSG_UNRECOVERABLE_EXCEPTION => {
                    let msg = m.to_unrecoverable_exception_info().unwrap();
                    let rip = msg.header.rip;
                    println!("Unrecoverable exception: rip: {:#x}", rip);
                    break;
                }
                unknown => {
                    println!("Unknown exit reason {unknown}");
                    break;
                }
            },
            Err(e) => {
                println!("Error: {:?}", e);
                break;
            }
        }
    }
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
    }
}

fn setup_initial_sregs(vcpu: &mut VcpuFd) {
    let mut sregs = vcpu.get_sregs().unwrap();
    sregs.cs.base = 0;
    sregs.cs.l = 1;
    sregs.cs.s = 1;
    sregs.cs.present = 1;
    sregs.cs.selector = 0;

    sregs.efer = EFER_LME | EFER_LMA;
    sregs.cr3 = GUEST_PHYSICAL_ADDR_BASE as u64;
    sregs.cr4 = (Cr4::CR4_ENABLE_PAE | Cr4::CR4_ENABLE_SSE | Cr4::CR4_UNMASKED_SSE).bits() as u64;
    sregs.cr0 = (Cr0::CR0_PROTECTED_MODE
        | Cr0::CR0_MONITOR_COPROCESSOR
        | Cr0::CR0_EXTENSION_TYPE
        | Cr0::CR0_NUMERIC_ERROR
        | Cr0::CR0_WRITE_PROTECT
        | Cr0::CR0_ALIGNMENT_MASK
        | Cr0::CR0_ENABLE_PAGING)
        .bits() as u64;
    vcpu.set_sregs(&sregs).unwrap();
}

fn setup_page_tables(memory_arena: &mut [u8]) {
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
    memory_arena[..8].copy_from_slice(&pml4e.0.to_le_bytes());

    // Create PDPT with only 1 PDPT entry
    let pdpte = PDPTEntry::new(pd_addr, PDPTFlags::P | PDPTFlags::RW);
    memory_arena[0x1000..0x1000 + 8].copy_from_slice(&pdpte.0.to_le_bytes());

    // Create 1 PD table with only 512 PD entries
    for i in 0..512 {
        let pde = PDEntry::new(PAddr::from(i << 21), PDFlags::P | PDFlags::RW | PDFlags::PS); // 2 MB pages
        memory_arena[0x2000 + i * 8..0x2000 + i * 8 + 8].copy_from_slice(&pde.0.to_le_bytes());
    }
}

fn get_and_clear_dirty_pages(memory_size: usize, vm: &VmFd) -> Vec<u64> {
    let dirty_pages = vm
        .get_dirty_log(GUEST_PFN_BASE as u64, memory_size, 0b100)
        .unwrap();
    // println!("Dirty pages: {:#x?}", dirty_pages);
    dirty_pages
}

fn get_guest_binary_entrypoint_offset(code: &[u8]) -> usize {
    // let objdump = Command::new("objdump")
    //     .args(&["-d", "crates/guest/target/debug/guest"])
    //     .output()
    //     .expect(
    //         "failed to execute objdump. Did you compile the guest first, and is objdump installed?",
    //     );
    let offset = goblin::pe::PE::parse(code).unwrap().entry;
    // println!("entrypoint: {}", offset);
    // let objdump_str =
    //     String::from_utf8(objdump.stdout).expect("Failed to convert objdump output to string");
    // let entrypoint_line = objdump_str
    //     .lines()
    //     .find(|&line| line.contains("<_start>:"))
    //     .expect("Failed to find entrypoint in objdump output");

    // let entrypoint_line = entrypoint_line
    //     .split_whitespace()
    //     .nth(0)
    //     .expect("Failed to find entrypoint in objdump output");

    // let offset = usize::from_str_radix(entrypoint_line, 16)
    //     .expect("Failed to parse entrypoint offset as usize");
    // // println!("Entrypoint offset: {:#x}", offset);
    // offset
    offset
}

fn create_vm() -> (VmFd, VcpuFd) {
    let mshv = Mshv::new().unwrap();
    let pr = Default::default();
    let vm = mshv.create_vm_with_config(&pr).unwrap();
    vm.enable_dirty_page_tracking().unwrap();
    let vcpu = vm.create_vcpu(0).unwrap();
    (vm, vcpu)
}
