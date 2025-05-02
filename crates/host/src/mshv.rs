use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};

use mshv_bindings::{
    hv_message, hv_message_type_HVMSG_X64_HALT, hv_message_type_HVMSG_X64_IO_PORT_INTERCEPT,
    mshv_user_mem_region, SpecialRegisters, StandardRegisters,
};
use mshv_ioctls::Mshv;
use x86::controlregs::{Cr0, Cr4};

use crate::{shared::InterruptHandle, Registers, Vm, EFER_LMA, EFER_LME, GUEST_PHYSICAL_ADDR_BASE};

pub(crate) struct MshvVm {
    vm: mshv_ioctls::VmFd,
    vcpu: mshv_ioctls::VcpuFd,
    tid: Arc<AtomicU64>, // the thread the most recent `run` was called
    is_running: Arc<AtomicBool>,
}

pub(crate) fn create_vm() -> MshvVm {
    let mshv = Mshv::new().expect("unable to open /dev/mshv, are you running on kvm?");
    let pr = Default::default();
    let vm = mshv.create_vm_with_config(&pr).unwrap();
    vm.enable_dirty_page_tracking().unwrap();
    let vcpu = vm.create_vcpu(0).unwrap();
    MshvVm {
        vm,
        vcpu,
        tid: Arc::new(AtomicU64::new(0)),
        is_running: Arc::new(AtomicBool::new(false)),
    }
}

impl Vm for MshvVm {
    fn regs(&self) -> Registers {
        let regs = self.vcpu.get_regs().unwrap();
        Registers {
            rax: regs.rax,
            rbx: regs.rbx,
            rcx: regs.rcx,
            rdx: regs.rdx,
            rsi: regs.rsi,
            rdi: regs.rdi,
            rsp: regs.rsp,
            rbp: regs.rbp,
            r8: regs.r8,
            r9: regs.r9,
            r10: regs.r10,
            r11: regs.r11,
            r12: regs.r12,
            r13: regs.r13,
            r14: regs.r14,
            r15: regs.r15,
            rip: regs.rip,
            rflags: regs.rflags,
        }
    }

    fn set_regs(&self, regs: &Registers) {
        let mshv_regs = StandardRegisters {
            rax: regs.rax,
            rbx: regs.rbx,
            rcx: regs.rcx,
            rdx: regs.rdx,
            rsi: regs.rsi,
            rdi: regs.rdi,
            rsp: regs.rsp,
            rbp: regs.rbp,
            r8: regs.r8,
            r9: regs.r9,
            r10: regs.r10,
            r11: regs.r11,
            r12: regs.r12,
            r13: regs.r13,
            r14: regs.r14,
            r15: regs.r15,
            rip: regs.rip,
            rflags: regs.rflags,
        };
        self.vcpu.set_regs(&mshv_regs).unwrap();
    }

    fn map_memory_mshv(&self, region: mshv_user_mem_region) {
        self.vm.map_user_memory(region).unwrap()
    }

    fn run_until_halt_or_err(&mut self) {
        loop {
            self.tid
                .store(unsafe { libc::pthread_self() }, Ordering::Relaxed);
            self.is_running.store(true, Ordering::Relaxed);

            match self
                .vcpu
                .run(hv_message::default())
                .inspect(|_| self.is_running.store(false, Ordering::Relaxed))
                .inspect_err(|_| self.is_running.store(false, Ordering::Relaxed))
            {
                Ok(m) => match m.header.message_type {
                    hv_message_type_HVMSG_X64_IO_PORT_INTERCEPT => {
                        let msg = m.to_ioport_info().unwrap();
                        let port = msg.port_number;
                        let data = msg.rax;
                        println!("io port intercept on port {}, with value: {:?}", port, data);
                    }
                    hv_message_type_HVMSG_X64_HALT => {
                        println!("Vcpu halted");
                        break;
                    }
                    unknown => {
                        println!("Unknown exit reason: {:#?}", unknown);
                        break;
                    }
                },
                Err(e) => {
                    if e.errno() == libc::EINTR {
                        println!("Vcpu interrupted");
                    } else {
                        println!("Unknown vcpu exit: Error: {:?}", e);
                    }
                    break;
                }
            }
        }
    }

    fn interrupt_handle(&self) -> InterruptHandle {
        InterruptHandle {
            tid: self.tid.clone(),
            is_running: self.is_running.clone(),
        }
    }

    fn sregs_mshv(&self) -> SpecialRegisters {
        self.vcpu.get_sregs().unwrap()
    }

    fn set_sregs_mshv(&self, sregs: &SpecialRegisters) {
        self.vcpu.set_sregs(sregs).unwrap()
    }

    fn sregs_kvm(&self) -> kvm_bindings::kvm_sregs {
        todo!()
    }

    fn set_sregs_kvm(&self, _sregs: &kvm_bindings::kvm_sregs) {
        todo!()
    }

    fn map_memory_kvm(&self, _region: kvm_bindings::kvm_userspace_memory_region) {
        todo!()
    }
}

pub(crate) fn setup_initial_sregs_mshv(vcpu: &mut impl Vm) {
    let mut sregs = vcpu.sregs_mshv();
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
    vcpu.set_sregs_mshv(&sregs);
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
