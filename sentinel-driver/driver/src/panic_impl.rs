#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // In kernel mode, a panic = BSOD. We use `panic = "abort"` in Cargo.toml
    // so this should never be reached. If it is, halt immediately.
    //
    // Bug check code 0xDEADBEEF is a custom sentinel value — not a standard
    // Windows stop code — so it's immediately identifiable in crash dumps.
    unsafe {
        wdk_sys::ntddk::KeBugCheckEx(0xDEAD_BEEF, 0, 0, 0, 0);
    }
}
