use confidential_assets::bcs_serialize_move_vector_u8;

#[test]
fn bcs_vector_u8_is_uleb128_length_plus_bytes() {
    let bytes = bcs_serialize_move_vector_u8(&[1, 2, 3]);
    assert_eq!(bytes[0], 3);
    assert_eq!(&bytes[1..], &[1u8, 2, 3]);
}
