use super::*;

#[test]
fn test_to_and_from_bytes() -> Result<()> {
    let kp = SampiKeyPair::new();
    let data = "Hello, World".as_bytes().to_vec();
    let s = kp.new_sampi().build(&data[..])?;
    assert_eq!(s.data, data);

    let bytes = s.to_bytes();
    assert_eq!(Sampi::from_bytes(&bytes)?.to_bytes()[2..], bytes[2..]);
    Ok(())
}

#[test]
fn test_to_and_from_bytes_with_additional_bytes() -> Result<()> {
    let kp = SampiKeyPair::new();
    let data = "Hello, World".as_bytes().to_vec();
    let s = kp.new_sampi().build(&data[..])?;
    assert_eq!(s.data, data);

    let mut bytes = s.to_bytes();
    let original_bytes_length = bytes.len();
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    assert_eq!(
        Sampi::from_bytes(&bytes)?.to_bytes()[2..],
        bytes[2..original_bytes_length]
    );
    Ok(())
}

#[test]
fn test_to_and_from_base64() -> Result<()> {
    let kp = SampiKeyPair::new();
    let data = "Hello, World".as_bytes().to_vec();
    let s = kp.new_sampi().build(&data[..])?;
    assert_eq!(s.data, data);

    let base64 = s.to_base64();
    assert_eq!(Sampi::from_base64(&base64)?.to_base64()[6..], base64[6..]);
    Ok(())
}

#[test]
fn test_to_and_from_hex() -> Result<()> {
    let kp = SampiKeyPair::new();
    let data = "Hello, World".as_bytes().to_vec();
    let s = kp.new_sampi().build(&data[..])?;
    assert_eq!(s.data, data);

    let hex = s.to_hex();
    assert_eq!(Sampi::from_hex(&hex)?.to_hex()[4..], hex[4..]);
    Ok(())
}

#[test]
fn test_data_sizes() -> Result<()> {
    let kp = SampiKeyPair::new();
    assert!(kp.new_sampi().build(vec![]).is_ok());
    assert!(kp.new_sampi().build(vec![0; 900]).is_ok());
    assert!(kp.new_sampi().build(vec![0; 901]).is_err());
    Ok(())
}

#[test]
fn test_pow() -> Result<()> {
    let kp = SampiKeyPair::new();
    let s = kp.new_sampi().with_pow(20).build(vec![])?;
    assert!(s.get_pow_score() >= 20);
    let base64 = s.to_base64();
    assert!(Sampi::from_base64(&base64).is_ok());
    assert!(Sampi::from_base64_with_pow_check(&base64, 0).is_ok());
    assert!(Sampi::from_base64_with_pow_check(&base64, 250).is_err());
    Ok(())
}

#[test]
fn test_one_thread_pow() -> Result<()> {
    let kp = SampiKeyPair::new();
    let s = kp
        .new_sampi()
        .with_pow(20)
        .with_pow_threads(1)
        .build(vec![])?;
    assert!(s.get_pow_score() >= 20);
    let base64 = s.to_base64();
    assert!(Sampi::from_base64(&base64).is_ok());
    assert!(Sampi::from_base64_with_pow_check(&base64, 0).is_ok());
    assert!(Sampi::from_base64_with_pow_check(&base64, 250).is_err());
    Ok(())
}

#[test]
fn test_utf8() -> Result<()> {
    let kp = SampiKeyPair::new();
    let my_string = "Hello, World";
    let data = my_string.as_bytes().to_vec();
    let s = kp.new_sampi().build(&data[..])?;

    assert_eq!(s.data, data);
    assert_eq!(s.data_as_string()?, my_string);
    Ok(())
}

#[test]
fn test_from_str() -> Result<()> {
    let kp = SampiKeyPair::new();
    let s = kp.new_sampi().build(vec![1, 2, 3])?;
    let base64 = s.to_base64();
    let hex = s.to_hex();

    assert_eq!(Sampi::from_str(&base64)?.data, Sampi::from_str(&hex)?.data);
    Ok(())
}

#[test]
fn test_nesting() -> Result<()> {
    let kp = SampiKeyPair::new();
    let s_1 = kp.new_sampi().build(vec![1, 2, 3])?;
    let s_2 = kp.new_sampi().build(s_1.to_bytes())?;
    let s_3 = Sampi::from_bytes(&s_2.data)?;
    assert_eq!(s_1.data, s_3.data);
    assert_eq!(s_1.get_unix_time(), s_3.get_unix_time());
    assert_eq!(s_1.to_bytes(), s_3.to_bytes());
    assert_eq!(s_1.get_hash(), s_3.get_hash());
    assert_eq!(s_3.data, vec![1, 2, 3]);
    Ok(())
}

#[test]
fn test_bincode_storage() -> Result<()> {
    let kp = SampiKeyPair::new();
    let v = (1, 2.0, 'a');
    let bincoded = bincode::serialize(&v)?;

    let s_1 = kp.new_sampi().build(&bincoded[..])?;
    let s_2 = Sampi::from_hex(&s_1.to_hex())?;

    let decoded_v = bincode::deserialize(&s_2.data)?;
    assert_eq!(v, decoded_v);
    Ok(())
}

#[test]
fn test_ordering() -> Result<()> {
    let kp = SampiKeyPair::new();
    let mut sampis: Vec<_> = vec![5, 4, 3, 2, 1]
        .into_iter()
        .map(|i| kp.new_sampi().with_unix_time(i).build(vec![]).unwrap())
        .collect();
    assert_eq!(sampis[0].get_unix_time(), 5);
    sampis.sort();
    assert_eq!(
        sampis.iter().map(|s| s.get_unix_time()).collect::<Vec<_>>(),
        (1..=5).collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
fn test_filtering() -> Result<()> {
    let kp = SampiKeyPair::new();
    let sampis: Vec<_> = vec![5, 4, 3, 2, 1]
        .into_iter()
        .map(|i| kp.new_sampi().with_unix_time(i).build(vec![]).unwrap())
        .collect();

    let mut filter = SampiFilter::new();
    filter.maximum_unix_time = Some(3);

    assert_eq!(sampis.into_iter().filter(|s| filter.matches(s)).count(), 3);
    Ok(())
}
