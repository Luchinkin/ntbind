//! Sample driver consuming the ntbind-generated SDK.  Calls DbgPrint
//! with a banner, walks PsActiveProcessHead through the SDK
//! accessors, prints up to eight image names and the total count.

#![no_std]

use core::ffi::c_void;
use core::mem;
use core::panic::PanicInfo;
use core::ptr;

use ntbind::nt::{ListEntryT, containing_record};
use ntbind_sys::nt::EprocessT;
use ntbind_sys::nt::api as nt;

const STATUS_SUCCESS: i32 = 0;
const MAX_PROCESSES_LOGGED: usize = 8;
// Hard ceiling so a corrupted Flink chain that never returns to the
// head still terminates.
const PROCESS_WALK_HARD_LIMIT: usize = 4096;

// Fixed-arity ABI shim for variadic DbgPrint.  Stable Rust cannot name
// a variadic function-pointer type; on Win64 the variadic ABI passes
// the first four args in RCX/RDX/R8/R9 regardless, so a three-fixed-
// arg `extern "C" fn` is interchangeable with
// `int DbgPrint(const char*, ...)` for up to two extra args.
//
type DbgPrint3 = unsafe extern "C" fn(fmt: *const u8, a: usize, b: usize) -> i32;

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

// `DriverEntry` is the name the kernel I/O manager looks up by symbol;
// allow snake-case to keep the export literal.
//
#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DriverEntry(_: *mut c_void, _: *mut c_void) -> i32 {
    let Some(dbg) = resolve_dbg_print() else {
        return STATUS_SUCCESS;
    };
    // SAFETY: `dbg` is the resolved kernel DbgPrint; format strings
    // are static C strings; PASSIVE_LEVEL on entry.
    unsafe {
        dbg(c"[ntbind] sample driver loaded\n".as_ptr().cast(), 0, 0);
        log_self_process(dbg);
        walk_processes(dbg);
        dbg(c"[ntbind] sample driver init done\n".as_ptr().cast(), 0, 0);
    }
    STATUS_SUCCESS
}

// Demonstrates the typed-public path -- `PsGetCurrentProcess` is one of
// the kernel publics whose signature ntbindgen recovered from the PDB
// IPI stream (`LF_FUNC_ID` -> `LF_PROCEDURE`).  The SDK emits the
// accessor as `Public<unsafe extern "system" fn() -> *mut EprocessT>`,
// so `as_fn()` returns the typed pointer directly -- no `transmute`,
// no per-function type alias on the driver side.
//
// Compare with `resolve_dbg_print` below: DbgPrint is variadic, so the
// SDK falls back to `Public<c_void>` and the driver writes the type
// alias + transmute by hand.
unsafe fn log_self_process(dbg: DbgPrint3) {
    // SAFETY: the SDK already attached the matching function-pointer
    // type to `Public<F>`, so `as_fn` reads the resolved VA back into
    // exactly the ABI the kernel actually uses for this export.
    let Some(get_current_proc) = (unsafe { nt::ps_get_current_process().as_fn() }) else {
        return;
    };
    // SAFETY: `PsGetCurrentProcess` is no-arg and always safe at
    // PASSIVE_LEVEL; the returned EPROCESS pointer is valid for the
    // lifetime of the current thread.
    let proc_ptr = unsafe { get_current_proc() };
    // SAFETY: format string is a static C string.
    unsafe { dbg(c"[ntbind] self EPROCESS=%p\n".as_ptr().cast(), proc_ptr as usize, 0) };
}

fn resolve_dbg_print() -> Option<DbgPrint3> {
    let p = nt::dbg_print();
    if !p.is_present() {
        return None;
    }
    // SAFETY: see DbgPrint3 doc.
    Some(unsafe { mem::transmute::<usize, DbgPrint3>(p.addr() as usize) })
}

// Walks PsActiveProcessHead and prints up to MAX_PROCESSES_LOGGED
// entries' image names, then the total count.
//
// Caller must be at PASSIVE_LEVEL and the kernel publics must already
// have been resolved by the patcher.
//
unsafe fn walk_processes(dbg: DbgPrint3) {
    let head_va = nt::ps_active_process_head().addr();
    if head_va == 0 {
        unsafe { dbg(c"[ntbind] PsActiveProcessHead unresolved\n".as_ptr().cast(), 0, 0) };
        return;
    }
    let head = head_va as *const ListEntryT;

    // Typed-public demo with arguments.  `PsIsProcessAppContainer` is
    // emitted by ntbindgen from its PDB IPI signature as
    // `Public<unsafe extern "system" fn(*mut EprocessT) -> u8>`.  No
    // hand-written `type` alias on the driver side, and the typed
    // `*mut EprocessT` arg flows straight from our `containing_record`
    // call below -- no cast.
    //
    // SAFETY: the SDK already attached the matching ABI to `Public<F>`.
    let is_app_container = unsafe { nt::ps_is_process_app_container().as_fn() };

    let mut walked = 0usize;
    // SAFETY: head is the kernel's PsActiveProcessHead; `iter()`
    // walks the active-process chain and `take` bounds a corrupted
    // chain.  Each yielded node is an `EPROCESS.ActiveProcessLinks`.
    let entries = unsafe { (*head).iter() }.take(PROCESS_WALK_HARD_LIMIT);
    for (i, node) in entries.enumerate() {
        walked = i + 1;
        if i < MAX_PROCESSES_LOGGED {
            let eproc =
                containing_record::<EprocessT>(node.cast(), EprocessT::ACTIVE_PROCESS_LINKS_OFFSET);
            // SAFETY: eproc points at an active-list EPROCESS; both
            // fields are live for the duration of the read.
            let pid = unsafe { ptr::read_volatile((*eproc).unique_process_id()) } as usize;
            let name = unsafe { (*eproc).image_file_name() } as *const u8 as usize;
            // SAFETY: PASSIVE_LEVEL on entry; `eproc` is a live
            // EPROCESS pointer from the active-process list.
            // Cast `*const -> *mut`: the typed signature recovered from
            // the PDB IPI made this mismatch a compile-time error
            // instead of silent UB through an untyped `*mut c_void`.
            let ac =
                is_app_container.map_or(usize::MAX, |f| unsafe { f(eproc.cast_mut()) } as usize);
            // SAFETY: format string is a static C string; varargs
            // shape matches `DbgPrint3` (3 trailing args).
            unsafe {
                dbg_4(dbg, c"[ntbind]   pid=%zu name=%.15s ac=%zu\n".as_ptr().cast(), pid, name, ac)
            };
        }
    }
    // SAFETY: see above.
    unsafe { dbg(c"[ntbind] walked %zu process(es)\n".as_ptr().cast(), walked, 0) };
}

// Stable-Rust fixed-arity wrapper for the 4-arg DbgPrint shape.
// Win64 routes the first four arguments via RCX/RDX/R8/R9 regardless of
// the callee's variadic signature, so casting a 4-arg `extern "C" fn`
// onto the resolved `DbgPrint` VA works for any (fmt, a, b, c) call.
//
// SAFETY: caller ensures `f`, `fmt`, and trailing arg interpretations
// match the underlying DbgPrint contract.
unsafe fn dbg_4(f: DbgPrint3, fmt: *const u8, a: usize, b: usize, c: usize) -> i32 {
    type DbgPrint4 = unsafe extern "C" fn(*const u8, usize, usize, usize) -> i32;
    // SAFETY: re-typing the same code address; both signatures use the
    // C ABI and Win64 passes args through registers, not the stack.
    let f4: DbgPrint4 = unsafe { mem::transmute::<DbgPrint3, DbgPrint4>(f) };
    unsafe { f4(fmt, a, b, c) }
}
