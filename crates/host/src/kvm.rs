use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};

use kvm_bindings::{kvm_regs, kvm_sregs};
use kvm_ioctls::VcpuExit;
use mshv_bindings::SpecialRegisters;
use x86::controlregs::{Cr0, Cr4};

use crate::{
    shared::{InterruptHandle, Registers, Vm},
    EFER_LMA, EFER_LME, GUEST_PHYSICAL_ADDR_BASE,
};

pub struct KvmVm {
    vm: kvm_ioctls::VmFd,
    vcpu: kvm_ioctls::VcpuFd,
    tid: Arc<AtomicU64>,         // the thread the most recent `run` was called
    is_running: Arc<AtomicBool>, // set to true while the vcpu is running (blocking)
}

pub fn create_vm() -> KvmVm {
    let kvm = kvm_ioctls::Kvm::new().expect("unable to open /dev/kvm, are you running on mshv?");
    let vm = kvm.create_vm().unwrap();
    let vcpu = vm.create_vcpu(0).unwrap();
    KvmVm {
        vm,
        vcpu,
        tid: Arc::new(AtomicU64::new(0)),
        is_running: Arc::new(AtomicBool::new(false)),
    }
}

impl Vm for KvmVm {
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
        let kvm_regs = kvm_regs {
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
        self.vcpu.set_regs(&kvm_regs).unwrap();
    }

    fn sregs_kvm(&self) -> kvm_sregs {
        self.vcpu.get_sregs().unwrap()
    }

    fn set_sregs_kvm(&self, sregs: &kvm_sregs) {
        self.vcpu.set_sregs(sregs).unwrap();
    }

    fn map_memory_kvm(&self, region: kvm_bindings::kvm_userspace_memory_region) {
        unsafe {
            self.vm
                .set_user_memory_region(region)
                .expect("Failed to set user memory region");
        }
    }

    fn run_until_halt_or_err(&mut self) {
        loop {
            self.tid
                .store(unsafe { libc::pthread_self() }, Ordering::Relaxed);
            self.is_running.store(true, Ordering::Relaxed);

            match self
                .vcpu
                .run()
                .inspect(|_| self.is_running.store(false, Ordering::Relaxed))
                .inspect_err(|_| self.is_running.store(false, Ordering::Relaxed))
            {
                Ok(m) => match m {
                    VcpuExit::IoOut(port, data) => {
                        println!("io port intercept on port {}, with value: {:?}", port, data);
                    }
                    VcpuExit::Hlt => {
                        println!("Vcpu halted");
                        break;
                    }
                    _ => {
                        println!("Unknown exit reason: {:?}", m);
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

    fn map_memory_mshv(&self, _region: mshv_bindings::mshv_user_mem_region) {
        panic!("called mshv on kvm struct")
    }

    fn sregs_mshv(&self) -> SpecialRegisters {
        panic!("called mshv on kvm struct")
    }

    fn set_sregs_mshv(&self, sregs: &mshv_bindings::SpecialRegisters) {
        panic!("called mshv on kvm struct")
    }
}

pub(crate) fn setup_initial_sregs_kvm(vm: &mut impl Vm) {
    let mut sregs = vm.sregs_kvm();
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
    vm.set_sregs_kvm(&sregs);
}
