struct MshvVm {
    vm: mshv_ioctls::VmFd,
    vcpu: mshv_ioctls::VcpuFd,
}
impl Vm for MshvVm {}

#[cfg(feature = "mshv")]
fn create_vm() -> (VmFd, VcpuFd) {
    let mshv = Mshv::new().unwrap();
    let pr = Default::default();
    let vm = mshv.create_vm_with_config(&pr).unwrap();
    vm.enable_dirty_page_tracking().unwrap();
    let vcpu = vm.create_vcpu(0).unwrap();
    (vm, vcpu)
}

fn setup_initial_sregs(vcpu: &mut impl Vm) {
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

// map memory into vm
// vm.map_user_memory(mshv_user_mem_region {
//     guest_pfn: GUEST_PFN_BASE as u64,
//     size: memory_size as u64,
//     userspace_addr: memory_arena_raw as u64,
//     flags: HV_MAP_GPA_READABLE | HV_MAP_GPA_WRITABLE | HV_MAP_GPA_EXECUTABLE,
// })
// .unwrap();
// #[allow(non_upper_case_globals)]
// fn execute_until_halt(vcpu: &mut impl Vm) {
//     // Run CPU until halt
//     loop {
//         let hv_message: hv_message = unsafe { std::mem::zeroed() };
//         match vcpu.run(hv_message) {
//             Ok(m) => match m.header.message_type {
//                 hv_message_type_HVMSG_X64_HALT => {
//                     // println!("Vcpu halted");
//                     break;
//                 }
//                 hv_message_type_HVMSG_X64_IO_PORT_INTERCEPT => {
//                     let io = m.to_ioport_info().unwrap();
//                     let port = io.port_number;
//                     let val = io.rax;
//                     let mut regs = vcpu.get_regs().unwrap();
//                     regs.rip += 1;
//                     vcpu.set_regs(&regs).unwrap();
//                     println!("io port intercept on port {}, with value: {}", port, val);
//                 }
//                 hv_message_type_HVMSG_UNMAPPED_GPA => {
//                     let mimo_message = m.to_memory_info().unwrap();
//                     let paddr = mimo_message.guest_physical_address;
//                     let vaddr = mimo_message.guest_virtual_address;
//                     let rip = mimo_message.header.rip;
//                     println!(
//                         "Unmapped gpa! paddr: {:#x} vaddr: {:#x}, rip: {:#x}",
//                         paddr, vaddr, rip
//                     );
//                     break;
//                 }
//                 hv_message_type_HVMSG_UNRECOVERABLE_EXCEPTION => {
//                     let msg = m.to_unrecoverable_exception_info().unwrap();
//                     let rip = msg.header.rip;
//                     println!("Unrecoverable exception: rip: {:#x}", rip);
//                     break;
//                 }
//                 unknown => {
//                     println!("Unknown exit reason {unknown}");
//                     break;
//                 }
//             },
//             Err(e) => {
//                 println!("Error: {:?}", e);
//                 break;
//             }
//         }
//     }
// }
