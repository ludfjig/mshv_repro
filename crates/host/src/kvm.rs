use kvm_bindings::{kvm_regs, kvm_sregs};
use kvm_ioctls::VcpuExit;
use libc::SIGUSR1;
use x86::controlregs::{Cr0, Cr4};

use crate::{
    shared::{InterruptHandle, Registers, Vm},
    EFER_LMA, EFER_LME, GUEST_PHYSICAL_ADDR_BASE,
};

#[cfg(feature = "kvm")]
pub fn create_vm() -> KvmVm {
    let kvm = kvm_ioctls::Kvm::new().unwrap();
    let vm = kvm.create_vm().unwrap();
    let vcpu = vm.create_vcpu(0).unwrap();
    KvmVm {
        vm,
        vcpu,
        tid: None,
    }
}

pub struct KvmVm {
    vm: kvm_ioctls::VmFd,
    vcpu: kvm_ioctls::VcpuFd,
    tid: Option<u64>, // the thread the most recent `run` was called
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

    fn sregs(&self) -> kvm_sregs {
        self.vcpu.get_sregs().unwrap()
    }

    fn set_sregs(&self, sregs: &kvm_sregs) {
        self.vcpu.set_sregs(sregs).unwrap();
    }

    fn map_memory(&self, region: kvm_bindings::kvm_userspace_memory_region) {
        unsafe {
            self.vm
                .set_user_memory_region(region)
                .expect("Failed to set user memory region");
        }
    }

    fn run(&mut self) {
        // Run CPU until halt

        loop {
            self.tid.replace(unsafe { libc::pthread_self() });
            match self.vcpu.run() {
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
                    println!("Unknown exit: Error: {:?}", e);
                    break;
                }
            }
        }
    }

    fn interrupt_handle(&self) -> InterruptHandle {
        InterruptHandle { vm: self }
    }

    fn kill(&self) -> Result<(), ()> {
        println!("Sending SIGUSR1 to thread on which VM is running...");
        unsafe { libc::pthread_kill(self.tid.unwrap(), SIGUSR1) };
        Ok(())
    }
}

pub(crate) fn setup_initial_sregs(vm: &mut dyn Vm) {
    let mut sregs = vm.sregs();
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
    vm.set_sregs(&sregs);
}
