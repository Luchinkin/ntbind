//! Loaded-module enumeration on the running Windows kernel and within
//! the patcher's own user-mode process; backs `--auto-modules`.

use std::collections::HashMap;

use anyhow::Result;

/// Enumerates kernel-mode modules loaded on the running system,
/// returning `{image_name_lowercase => base_va}`.  Non-Windows targets
/// return an error.
#[cfg(windows)]
pub fn loaded_drivers() -> Result<HashMap<String, u64>> {
    use std::ffi::c_void;
    use std::mem;
    use std::ptr;

    use anyhow::{Context, bail};
    use windows_sys::Win32::System::ProcessStatus::{EnumDeviceDrivers, GetDeviceDriverBaseNameA};

    // First call: ask how many bytes the kernel needs to hand back.
    let mut needed: u32 = 0;
    let ok = unsafe { EnumDeviceDrivers(ptr::null_mut(), 0, &mut needed) };
    if ok == 0 {
        bail!("EnumDeviceDrivers(size probe) returned FALSE -- need admin?");
    }
    let ptr_size = mem::size_of::<*mut c_void>();
    let count = needed as usize / ptr_size;
    if count == 0 {
        return Ok(HashMap::new());
    }

    // Pull the actual base-address vector.
    let mut bases: Vec<*mut c_void> = vec![ptr::null_mut(); count];
    let bytes = (bases.len() * ptr_size) as u32;
    let ok = unsafe { EnumDeviceDrivers(bases.as_mut_ptr().cast(), bytes, &mut needed) };
    if ok == 0 {
        bail!("EnumDeviceDrivers(fill) returned FALSE");
    }

    let mut out = HashMap::with_capacity(count);
    let mut name_buf = [0u8; 260];
    for (i, &base) in bases.iter().enumerate() {
        if base.is_null() {
            continue;
        }
        let n =
            unsafe { GetDeviceDriverBaseNameA(base, name_buf.as_mut_ptr(), name_buf.len() as u32) };
        if n == 0 {
            continue;
        }
        let name = std::str::from_utf8(&name_buf[..n as usize])
            .with_context(|| format!("driver name at index {i} is not UTF-8"))?
            .to_ascii_lowercase();
        out.insert(name, base as u64);
    }
    Ok(out)
}

#[cfg(not(windows))]
pub fn loaded_drivers() -> Result<HashMap<String, u64>> {
    anyhow::bail!("--auto-modules requires running on Windows");
}

/// Enumerates user-mode modules loaded in the *current* (patcher)
/// process, returning `{image_name_lowercase => base_va}`.  Useful
/// when the patcher runs inside (or is launched alongside) the
/// process that will host the patched binary; the patcher's own DLLs
/// satisfy any reference the input PE shares with it.
///
/// On non-Windows targets the call returns an error.
#[cfg(windows)]
pub fn loaded_user_modules() -> Result<HashMap<String, u64>> {
    use std::ffi::c_void;
    use std::mem;
    use std::ptr;

    use anyhow::{Context, bail};
    use windows_sys::Win32::System::ProcessStatus::{
        EnumProcessModulesEx, GetModuleBaseNameA, LIST_MODULES_ALL,
    };

    // `GetCurrentProcess()` returns the pseudo-handle `(HANDLE)-1` --
    // hard-code it to avoid pulling in `Win32_System_Threading`.
    let proc: *mut c_void = !0 as *mut c_void;

    let mut needed: u32 = 0;
    let ok =
        unsafe { EnumProcessModulesEx(proc, ptr::null_mut(), 0, &mut needed, LIST_MODULES_ALL) };
    if ok == 0 {
        bail!("EnumProcessModulesEx(size probe) returned FALSE");
    }
    let ptr_size = mem::size_of::<*mut c_void>();
    let count = needed as usize / ptr_size;
    if count == 0 {
        return Ok(HashMap::new());
    }

    let mut modules: Vec<*mut c_void> = vec![ptr::null_mut(); count];
    let bytes = (modules.len() * ptr_size) as u32;
    let ok = unsafe {
        EnumProcessModulesEx(
            proc,
            modules.as_mut_ptr().cast(),
            bytes,
            &mut needed,
            LIST_MODULES_ALL,
        )
    };
    if ok == 0 {
        bail!("EnumProcessModulesEx(fill) returned FALSE");
    }

    let mut out = HashMap::with_capacity(count);
    let mut name_buf = [0u8; 260];
    for (i, &hmodule) in modules.iter().enumerate() {
        if hmodule.is_null() {
            continue;
        }
        let n = unsafe {
            GetModuleBaseNameA(proc, hmodule, name_buf.as_mut_ptr(), name_buf.len() as u32)
        };
        if n == 0 {
            continue;
        }
        let name = std::str::from_utf8(&name_buf[..n as usize])
            .with_context(|| format!("module name at index {i} is not UTF-8"))?
            .to_ascii_lowercase();
        out.insert(name, hmodule as u64);
    }
    Ok(out)
}

#[cfg(not(windows))]
pub fn loaded_user_modules() -> Result<HashMap<String, u64>> {
    anyhow::bail!("--auto-modules requires running on Windows");
}
