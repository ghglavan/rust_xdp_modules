#[repr(C, packed)]
#[no_mangle]
pub struct ethhdr {
    pub h_dest: [u8; 6],
    pub h_source: [u8; 6],
    pub h_proto: u16,
}

#[macro_export]
macro_rules! ethhdr_from_raw {
    ($raw:expr) => {{
        let mut eth = unsafe { $raw as *mut ethhdr };
        let mut eth = unsafe { &*eth };
        eth
    }};
}
