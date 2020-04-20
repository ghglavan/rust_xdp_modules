#[repr(C)]
#[no_mangle]
pub struct bpf_spin_lock {
    pub val: u32,
}

#[repr(C)]
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
pub struct xdp_md {
    pub data: u32,
    pub data_end: u32,
    pub data_meta: u32,
    /* Below access go through struct xdp_rxq_info */
    pub ingress_ifindex: u32, /* rxq->dev->ifindex */
    pub rx_queue_index: u32,  /* rxq->queue_index  */
}
