use zorph_crypto::wipe::{wipe, wipe_vec, wipe_array, SecureBuffer};

#[test]
fn wipe_slice() {
    let mut data = vec![0xFFu8; 32];
    wipe(&mut data);
    assert!(data.iter().all(|&b| b == 0));
}

#[test]
fn wipe_vec_zeros() {
    let mut data = vec![0xABu8; 64];
    wipe_vec(&mut data);
    assert!(data.is_empty() || data.iter().all(|&b| b == 0));
}

#[test]
fn wipe_fixed_array() {
    let mut data = [0xCDu8; 32];
    wipe_array(&mut data);
    assert!(data.iter().all(|&b| b == 0));
}

#[test]
fn secure_buffer_basic() {
    let buf = SecureBuffer::new(vec![1, 2, 3, 4, 5]);
    assert_eq!(buf.len(), 5);
    assert_eq!(buf.as_bytes(), &[1, 2, 3, 4, 5]);
}

#[test]
fn secure_buffer_from_slice() {
    let buf = SecureBuffer::from_slice(&[10, 20, 30]);
    assert_eq!(buf.as_bytes(), &[10, 20, 30]);
}

#[test]
fn secure_buffer_is_empty() {
    let empty = SecureBuffer::new(vec![]);
    assert!(empty.is_empty());

    let full = SecureBuffer::new(vec![1]);
    assert!(!full.is_empty());
}

#[test]
fn secure_buffer_as_ref() {
    let buf = SecureBuffer::new(vec![42]);
    let r: &[u8] = buf.as_ref();
    assert_eq!(r, &[42]);
}

#[test]
fn secure_buffer_from_string() {
    let buf: SecureBuffer = String::from("secret password").into();
    assert_eq!(buf.as_bytes(), b"secret password");
}

#[test]
fn secure_buffer_from_vec() {
    let buf: SecureBuffer = vec![1u8, 2, 3].into();
    assert_eq!(buf.as_bytes(), &[1, 2, 3]);
}

#[test]
fn secure_buffer_from_byte_slice() {
    let data: &[u8] = &[10, 20, 30];
    let buf: SecureBuffer = data.into();
    assert_eq!(buf.as_bytes(), &[10, 20, 30]);
}

#[test]
fn secure_buffer_as_mut() {
    let mut buf = SecureBuffer::new(vec![1, 2, 3]);
    let m: &mut [u8] = buf.as_mut();
    m[0] = 99;
    assert_eq!(buf.as_bytes(), &[99, 2, 3]);
}
