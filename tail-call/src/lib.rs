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

#[no_mangle]
#[link_section = "maps"]
pub static xdp_progs_map: bpf_map_def = bpf_map_def {
    type_: BPF_MAP_TYPE_PROG_ARRAY,
    key_size: 4_u32,
    value_size: 4_u32,
    max_entries: 10_u32,
    map_flags: 0_u32,
};

#[no_mangle]
#[link_section = "xdp_tail_call1"]
#[allow(non_snake_case)]
pub extern "C" fn xdp_tail_call(_ctx: xdp_md) -> i32 {
    let bpf_trace_printk = init_bpf_trace_printk!();

    let msg = *b"in tail call 1 function\n\0";
    bpf_trace_printk((&msg).as_ptr(), 25);

    1
}
