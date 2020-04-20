#[macro_export]
pub mod ether;

#[cfg(test)]
mod tests {
    #[test]
    fn test_ether_is_14_bytes() {
        assert_eq!(std::mem::size_of::<crate::ether::ethhdr>(), 14);
    }

    #[test]
    fn test_ethhdr_from_bytes() {
        use crate::ether::*;

        let bytes: [u8; 14] = [
            0xfe, 0xff, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x00,
        ];
        let b = unsafe { &bytes as *const ::std::os::raw::c_uchar as *mut ::std::os::raw::c_uchar };
        let eth = crate::ethhdr_from_raw!(b);

        for i in 0..5 {
            assert!(eth.h_dest[i] == bytes[i]);
        }

        for i in 6..11 {
            assert!(eth.h_source[i - 6] == bytes[i]);
        }

        assert!(eth.h_proto == 0x0800_u16.to_be());
    }
}
