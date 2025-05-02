use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};

use kvm_bindings::{kvm_sregs, kvm_userspace_memory_region};
use libc::SIGUSR1;
use mshv_bindings::{mshv_user_mem_region, SpecialRegisters};

pub(crate) trait Vm: Send + Sync {
    fn regs(&self) -> Registers;
    fn set_regs(&self, regs: &Registers);

    // unify these
    fn sregs_kvm(&self) -> kvm_sregs;
    fn sregs_mshv(&self) -> SpecialRegisters;

    // unify these
    fn set_sregs_kvm(&self, sregs: &kvm_sregs);
    fn set_sregs_mshv(&self, sregs: &SpecialRegisters);

    // TODO unify these
    fn map_memory_kvm(&self, region: kvm_userspace_memory_region);
    fn map_memory_mshv(&self, region: mshv_user_mem_region);

    fn run_until_halt_or_err(&mut self);

    fn interrupt_handle(&self) -> InterruptHandle;
}

pub(crate) struct InterruptHandle {
    pub(crate) tid: Arc<AtomicU64>,
    pub(crate) is_running: Arc<AtomicBool>,
}

unsafe impl Send for InterruptHandle {}
unsafe impl Sync for InterruptHandle {}

impl InterruptHandle {
    pub(crate) fn interrupt_vm_if_running(&self) {
        println!("Interrupting VM...");
        if self.is_running.load(Ordering::Relaxed) {
            println!("Sending SIGUSR1 to thread on which VM is running...");
            // will cause blocking run call to exit with EINTR
            unsafe { libc::pthread_kill(self.tid.load(Ordering::Relaxed), SIGUSR1) };
        } else {
            println!("VM was not running, not interrupting..");
        }
    }
}

#[derive(Default)]
pub(crate) struct Registers {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}
