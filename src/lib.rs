use std::mem::{size_of, transmute};

#[no_mangle]
#[link_section = "license"]
pub static _license: [u8; 4] = [71u8, 80, 76, 0];

#[no_mangle]
#[link_section = "version"]
pub static _version: u32 = 0xFFFFFFFE;

pub type RBpfTracePrintk = extern "C" fn(*const u8, i32, ...) -> i32;

pub type RBpfMapLookupElem = extern "C" fn(
    *mut ::std::os::raw::c_void,
    *const ::std::os::raw::c_void,
) -> *mut ::std::os::raw::c_void;

pub type RBpfMapUpdateElem = extern "C" fn(
    *mut ::std::os::raw::c_void,
    *const ::std::os::raw::c_void,
    *const ::std::os::raw::c_void,
    u64,
) -> i32;

pub type RBpfSpinLock = extern "C" fn(*mut bpf_spin_lock) -> i32;

pub type RBpfSpinUnLock = extern "C" fn(*mut bpf_spin_lock) -> i32;

#[repr(C)]
#[no_mangle]
pub struct bpf_spin_lock {
    val: u32,
}

pub const BPF_MAP_TYPE_UNSPEC: bpf_map_type = 0;
pub const BPF_MAP_TYPE_HASH: bpf_map_type = 1;
pub const BPF_MAP_TYPE_ARRAY: bpf_map_type = 2;
pub const BPF_MAP_TYPE_PROG_ARRAY: bpf_map_type = 3;
pub const BPF_MAP_TYPE_PERF_EVENT_ARRAY: bpf_map_type = 4;
pub const BPF_MAP_TYPE_PERCPU_HASH: bpf_map_type = 5;
pub const BPF_MAP_TYPE_PERCPU_ARRAY: bpf_map_type = 6;
pub const BPF_MAP_TYPE_STACK_TRACE: bpf_map_type = 7;
pub const BPF_MAP_TYPE_CGROUP_ARRAY: bpf_map_type = 8;
pub const BPF_MAP_TYPE_LRU_HASH: bpf_map_type = 9;
pub const BPF_MAP_TYPE_LRU_PERCPU_HASH: bpf_map_type = 10;
pub const BPF_MAP_TYPE_LPM_TRIE: bpf_map_type = 11;
pub const BPF_MAP_TYPE_ARRAY_OF_MAPS: bpf_map_type = 12;
pub const BPF_MAP_TYPE_HASH_OF_MAPS: bpf_map_type = 13;
pub const BPF_MAP_TYPE_DEVMAP: bpf_map_type = 14;
pub const BPF_MAP_TYPE_SOCKMAP: bpf_map_type = 15;
pub const BPF_MAP_TYPE_CPUMAP: bpf_map_type = 16;
pub const BPF_MAP_TYPE_XSKMAP: bpf_map_type = 17;
pub const BPF_MAP_TYPE_SOCKHASH: bpf_map_type = 18;
pub const BPF_MAP_TYPE_CGROUP_STORAGE: bpf_map_type = 19;
pub const BPF_MAP_TYPE_REUSEPORT_SOCKARRAY: bpf_map_type = 20;
pub const BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE: bpf_map_type = 21;
pub const BPF_MAP_TYPE_QUEUE: bpf_map_type = 22;
pub const BPF_MAP_TYPE_STACK: bpf_map_type = 23;
pub const BPF_MAP_TYPE_SK_STORAGE: bpf_map_type = 24;
pub const BPF_MAP_TYPE_DEVMAP_HASH: bpf_map_type = 25;
pub type bpf_map_type = u32;

#[no_mangle]
pub struct bpf_map_def {
    pub type_: ::std::os::raw::c_uint,
    pub key_size: ::std::os::raw::c_uint,
    pub value_size: ::std::os::raw::c_uint,
    pub max_entries: ::std::os::raw::c_uint,
    pub map_flags: ::std::os::raw::c_uint,
}

#[repr(C)]
#[no_mangle]
pub struct SpinLockMap {
    lock: bpf_spin_lock,
    map_val: u32,
}

//workaround for static assertion of a struct size
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

#[no_mangle]
#[repr(C)]
pub struct xdp_md {
    data: u32,
    data_end: u32,
    data_meta: u32,
    /* Below access go through struct xdp_rxq_info */
    ingress_ifindex: u32, /* rxq->dev->ifindex */
    rx_queue_index: u32,  /* rxq->queue_index  */
}

#[no_mangle]
#[link_section = "xdp"]
#[allow(non_snake_case)]
pub extern "C" fn xdp_printk(_ctx: xdp_md) -> i32 {
    let bpf_trace_printk: RBpfTracePrintk = unsafe { transmute::<u64, RBpfTracePrintk>(6) };
    let bpf_map_lookup_elem: RBpfMapLookupElem = unsafe { transmute::<u64, RBpfMapLookupElem>(1) };
    let bpf_map_update_elem: RBpfMapUpdateElem = unsafe { transmute::<u64, RBpfMapUpdateElem>(2) };
    let bpf_spin_lock: RBpfSpinLock = unsafe { transmute::<u64, RBpfSpinLock>(93) };
    let bpf_spin_unlock: RBpfSpinUnLock = unsafe { transmute::<u64, RBpfSpinUnLock>(94) };

    let msg = *b"helloo %d\n\0";
    let msg2 = *b"no val %d\n\0";

    bpf_trace_printk((&msg2).as_ptr(), 11, 1);

    let key = 0_u32;

    let i = bpf_map_lookup_elem(
        &xdp_test_map as *const bpf_map_def as *mut ::std::os::raw::c_void,
        &key as *const u32 as *const ::std::os::raw::c_void,
    );

    if i == ::std::ptr::null_mut() {
        let msg = *b"error lookup elem:  %d\n\0";
        bpf_trace_printk((&msg).as_ptr(), 24, i);
    } else {
        let m: *mut SpinLockMap = unsafe { transmute::<u64, *mut SpinLockMap>(i as u64) };
        let ret =
            unsafe { bpf_spin_lock(&(*m).lock as *const bpf_spin_lock as *mut bpf_spin_lock) };

        // if ret != 0 {
        //     let msg = *b"error on spinlock";
        //     bpf_trace_printk((&msg).as_ptr(), 17);
        // } else {
        //     let msg = *b"success on spinlock";
        //     bpf_trace_printk((&msg).as_ptr(), 19);
        // }

        unsafe { bpf_spin_unlock(&(*m).lock as *const bpf_spin_lock as *mut bpf_spin_lock) };
    }

    bpf_trace_printk((&msg2).as_ptr(), 11, 2);

    let v: *mut ::std::os::raw::c_void = bpf_map_lookup_elem(
        &xdp_test_map as *const bpf_map_def as *mut ::std::os::raw::c_void,
        &key as *const u32 as *const ::std::os::raw::c_void,
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
