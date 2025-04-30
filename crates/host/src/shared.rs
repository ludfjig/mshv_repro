use kvm_bindings::{kvm_sregs, kvm_userspace_memory_region, kvm_userspace_memory_region2};

pub(crate) trait Vm: Send + Sync {
    fn regs(&self) -> Registers;
    fn set_regs(&self, regs: &Registers);
    fn sregs(&self) -> kvm_sregs;
    fn set_sregs(&self, sregs: &kvm_sregs);

    fn map_memory(&self, region: kvm_userspace_memory_region);

    fn run(&mut self);

    fn interrupt_handle(&self) -> InterruptHandle;

    fn kill(&self) -> Result<(), ()>;
}

pub(crate) struct InterruptHandle {
    pub(crate) vm: *const dyn Vm,
}

unsafe impl Send for InterruptHandle {}
unsafe impl Sync for InterruptHandle {}

impl InterruptHandle {
    pub(crate) fn kill(&self) -> Result<(), ()> {
        unsafe { self.vm.as_ref().unwrap().kill() }
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
