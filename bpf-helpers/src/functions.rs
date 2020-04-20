use crate::structs::{bpf_spin_lock, xdp_md};

#[macro_export]
macro_rules! init_bpf_trace_printk {
    () => {
        unsafe { transmute::<u64, extern "C" fn(*const u8, u32, ...) -> i32>(6) }
    };
}

#[macro_export]
macro_rules! bpf_map_lookup_elem {
    ($map:expr, $key:expr) => {
        unsafe {
            (transmute::<
                u64,
                extern "C" fn(
                    *mut ::std::os::raw::c_void,
                    *const ::std::os::raw::c_void,
                ) -> *mut ::std::os::raw::c_void,
            >(1))($map, $key)
        };
    };
}

#[macro_export]
macro_rules! bpf_map_update_elem {
    ($map:expr, $key:expr, $val:expr, $flags:expr) => {
        unsafe {
            (transmute::<
                u64,
                extern "C" fn(
                    *mut ::std::os::raw::c_void,
                    *const ::std::os::raw::c_void,
                    *const ::std::os::raw::c_void,
                    u64,
                ) -> i32,
            >(2))($map, $key, $val, $flags)
        };
    };
}

#[macro_export]
macro_rules! bpf_map_delete_elem {
    ($map:expr, $key:expr) => {
        unsafe {
            (transmute::<
                u64,
                extern "C" fn(*mut ::std::os::raw::c_void, *const ::std::os::raw::c_void) -> i32,
            >(3))($map, $key)
        };
    };
}

#[macro_export]
macro_rules! bpf_ktime_get_ns {
    () => {
        unsafe { (transmute::<u64, extern "C" fn() -> u64>(5))() };
    };
}

#[macro_export]
macro_rules! bpf_get_prandom_u32 {
    () => {
        unsafe { (transmute::<u64, extern "C" fn() -> u32>(7))() };
    };
}

#[macro_export]
macro_rules! bpf_tail_call {
    ($ctx:expr, $prog_array_map:expr, $index:expr) => {
        unsafe {
            (transmute::<
                u64,
                extern "C" fn(*mut ::std::os::raw::c_void, *mut ::std::os::raw::c_void, u32) -> i32,
            >(12))($ctx, $prog_array_map, $index)
        };
    };
}

#[macro_export]
macro_rules! bpf_redirect {
    ($ifindex:expr, $flags:expr) => {
        unsafe { (transmute::<u64, extern "C" fn(u32, u64) -> i32>(23))($ifindex, $flags) };
    };
}

#[macro_export]
macro_rules! bpf_xdp_adjust_head {
    ($xdp_md:expr, $delta:expr) => {
        unsafe { (transmute::<u64, extern "C" fn(*mut xdp_md, i32) -> i32>(44))($xdp_md, $delta) };
    };
}

#[macro_export]
macro_rules! bpf_redirect_map {
    ($map:expr, $key:expr, $flags:expr) => {
        unsafe {
            (transmute::<u64, extern "C" fn(*mut ::std::os::raw::c_void, u32, u64) -> i32>(51))(
                $map, $key, $flags,
            )
        };
    };
}

#[macro_export]
macro_rules! bpf_xdp_adjust_meta {
    ($xdp_md:expr, $delta:expr) => {
        unsafe { (transmute::<u64, extern "C" fn(*mut xdp_md, i32) -> i32>(54))($xdp_md, $delta) };
    };
}

#[macro_export]
macro_rules! bpf_xdp_adjust_tail {
    ($xdp_md:expr, $delta:expr) => {
        unsafe { (transmute::<u64, extern "C" fn(*mut xdp_md, i32) -> i32>(65))($xdp_md, $delta) };
    };
}

#[macro_export]
macro_rules! bpf_spin_lock {
    ($lock:expr) => {
        unsafe { (transmute::<u64, extern "C" fn(*mut bpf_spin_lock) -> i32>(93))($lock) };
    };
}

#[macro_export]
macro_rules! bpf_spin_unlock {
    ($lock:expr) => {
        unsafe { (transmute::<u64, extern "C" fn(*mut bpf_spin_lock) -> i32>(94))($lock) };
    };
}

#[macro_export]
macro_rules! bpf_strtol {
    ($buf:expr, $buf_len:expr, $flags:expr, $res:expr) => {
        unsafe { (transmute::<u64, extern "C" fn(*const ::std::os:raw::c_char, u64, u64, *mut i64) -> i32>(105))($bufm $buf_len, $flags, $res) };
    };
}

#[macro_export]
macro_rules! bpf_strtoul {
    ($buf:expr, $buf_len:expr, $flags:expr, $res:expr) => {
        unsafe { (transmute::<u64, extern "C" fn(*const ::std::os:raw::c_char, u64, u64, *mut u64) -> i32>(106))($bufm $buf_len, $flags, $res) };
    };
}

#[macro_export]
macro_rules! bpf_jiffies64 {
    () => {
        unsafe { (transmute::<u64, extern "C" fn() -> u64>(118))() };
    };
}
