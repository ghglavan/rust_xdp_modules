use bpf_helpers::map_types::*;
use bpf_helpers::structs::*;
use bpf_helpers::{
    bpf_map_lookup_elem, bpf_spin_lock, bpf_spin_unlock, bpf_tail_call, init_bpf_trace_printk,
};
use net_helpers::ether::*;
use net_helpers::ethhdr_from_raw;
use std::mem::transmute;

#[no_mangle]
#[link_section = "license"]
pub static _license: [u8; 4] = [71u8, 80, 76, 0];

#[no_mangle]
#[link_section = "version"]
pub static _version: u32 = 0xFFFFFFFE;

#[repr(C)]
#[no_mangle]
pub struct SpinLockMap {
    lock: bpf_spin_lock,
    map_val: u32,
}

// workaround for static assertion of a struct size
// mem::size_of is not a const function, so we cant use it inside a bpf_map_def
const SIZE_OF_SPINLOCKMAP: u32 = 8;
fn _static_assert() {
    unsafe { std::mem::transmute::<SpinLockMap, [u8; SIZE_OF_SPINLOCKMAP as usize]>(panic!()) };
}

#[no_mangle]
#[link_section = "maps"]
pub static xdp_test_map: bpf_map_def = bpf_map_def {
    type_: BPF_MAP_TYPE_ARRAY,
    key_size: 4_u32,
    value_size: SIZE_OF_SPINLOCKMAP,
    max_entries: 10_u32,
    map_flags: 0_u32,
};

#[no_mangle]
#[link_section = "maps"]
pub static xdp_progs_map: bpf_map_def = bpf_map_def {
    type_: BPF_MAP_TYPE_PROG_ARRAY,
    key_size: 4_u32,
    value_size: 4_u32,
    max_entries: 10_u32,
    map_flags: 0_u32,
};

// btf is needed so we can use spin locks. unfortunately, i count not get this
// working as a macro
#[repr(C)]
#[no_mangle]
pub struct ____btf_map_xdp_test_map {
    key: u32,
    value: SpinLockMap,
}

#[no_mangle]
#[link_section = ".maps.xdp_test_map"]
pub static ____btf_map_xdp_test_map: ____btf_map_xdp_test_map = ____btf_map_xdp_test_map {
    key: 0,
    value: SpinLockMap {
        lock: bpf_spin_lock { val: 0 },
        map_val: 0,
    },
};

// #[no_mangle]
// #[link_section = "xdp_tail_call_1"]
// pub extern "C" fn xdp_tail_c_1(_ctx: xdp_md) -> i32 {
//     let bpf_trace_printk = init_bpf_trace_printk!();
//     let msg = *b"bpf_tail_call_1\n\0";
//     bpf_trace_printk((&msg).as_ptr(), 17);

//     if _ctx.data_end - _ctx.data >= 14 {
//         let e = ethhdr_from_raw!(_ctx.data as *mut ::std::os::raw::c_uchar);
//     }

//     bpf_tail_call!(
//         &_ctx as *const xdp_md as *const ::std::os::raw::c_void as *mut ::std::os::raw::c_void,
//         &xdp_progs_map as *const bpf_map_def as *const ::std::os::raw::c_void
//             as *mut ::std::os::raw::c_void,
//         0
//     );

//     let msg = *b"bpf_tail_call_1 failed\n\0";
//     bpf_trace_printk((&msg).as_ptr(), 24);

//     0
// }

// #[no_mangle]
// #[link_section = "xdp_tail_call_2"]
// pub extern "C" fn xdp_tail_c_2(_ctx: xdp_md) -> i32 {
//     let bpf_trace_printk = init_bpf_trace_printk!();
//     let msg = *b"bpf_tail_call_2\n\0";
//     bpf_trace_printk((&msg).as_ptr(), 17);

//     0
// }

#[no_mangle]
#[link_section = "xdp"]
#[allow(non_snake_case)]
pub extern "C" fn xdp_printk(_ctx: xdp_md) -> i32 {
    // due to the fact that we cant take variable length arguments on macros 
    // and we want to keep everything in rust stable (so we cant use #![feature(const_transmute)])
    // bpf_trace_printk should be initialized at the begining of each function that uses it
    let bpf_trace_printk = init_bpf_trace_printk!();

    let msg = *b"helloo %d\n\0";
    let msg2 = *b"no val %d\n\0";

    bpf_trace_printk((&msg2).as_ptr(), 11, 1);
    let key = 0_u32;

    let i = bpf_map_lookup_elem!(
        &xdp_test_map as *const bpf_map_def as *mut ::std::os::raw::c_void,
        &key as *const u32 as *const ::std::os::raw::c_void
    );

    if i == ::std::ptr::null_mut() {
        let msg = *b"error lookup elem:  %d\n\0";
        bpf_trace_printk((&msg).as_ptr(), 24, i);
    } else {
        let m: *mut SpinLockMap = unsafe { transmute::<u64, *mut SpinLockMap>(i as u64) };
        let ret =
            unsafe { bpf_spin_lock!(&(*m).lock as *const bpf_spin_lock as *mut bpf_spin_lock) };
        unsafe { bpf_spin_unlock!(&(*m).lock as *const bpf_spin_lock as *mut bpf_spin_lock) };
    }

    bpf_trace_printk((&msg2).as_ptr(), 11, 2);

    let v: *mut ::std::os::raw::c_void = bpf_map_lookup_elem!(
        &xdp_test_map as *const bpf_map_def as *mut ::std::os::raw::c_void,
        &key as *const u32 as *const ::std::os::raw::c_void
    );

    if v == ::std::ptr::null_mut() {
        let msg = *b"could not lookup elem\n\0";
        bpf_trace_printk((&msg).as_ptr(), 23);
    }

    bpf_trace_printk((&msg2).as_ptr(), 11, 3);

    let v = unsafe { transmute::<*mut ::std::os::raw::c_void, *mut SpinLockMap>(v) };

    bpf_trace_printk((&msg2).as_ptr(), 11, 4);
    if v != ::std::ptr::null_mut() {
        unsafe {
            bpf_trace_printk((&msg).as_ptr(), 11, (*v).map_val);
        };
    } else {
        bpf_trace_printk((&(msg)).as_ptr(), 11, 3);
    }
    return 0;
}
