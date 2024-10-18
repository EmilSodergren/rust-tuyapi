#[test]
fn test_crc_calculation() {
    let crcval = crc32fast::hash(b"Hello World");
    assert_eq!(format!("{:x}", crcval), "4a17b156");
    let crcval = crc32fast::hash(b"ThisIsYuyaCalling");
    assert_eq!(format!("{:x}", crcval), "d6296f21");
    let crcval = crc32fast::hash(b"{devId: '002004265ccf7fb1b659', dps: {1: true, 2: 0}}");
    assert_eq!(format!("{:x}", crcval), "a524febe");
}
