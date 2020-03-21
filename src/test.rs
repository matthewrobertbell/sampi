use super::*;
use crate::SampiData;

#[test]
fn test_to_and_from_bytes() -> Result<()> {
    let kp = SampiKeyPair::new();
    let data = SampiData::String("Hello, World".to_string());
    let s = kp.new_sampi().build(data.clone())?;
    assert_eq!(s.data, data);

    let bytes = s.to_bytes();
    let derialized_s = Sampi::from_bytes(&bytes)?;
    assert_eq!(derialized_s.to_bytes()[2..], bytes[2..]);
    assert_eq!(s.serialized_length, derialized_s.serialized_length);
    assert_eq!(s.serialized_length, bytes.len() as u16);
    Ok(())
}

#[test]
fn test_from_str_parse() -> Result<()> {
    let kp = SampiKeyPair::new();
    let data = SampiData::String("Hello, World".to_string());
    let s = kp.new_sampi().build(data.clone())?;
    assert_eq!(s.data, data);

    let s_2: Sampi = s.to_base64().parse()?;
    assert_eq!(s.data, s_2.data);
    Ok(())
}

#[test]
fn test_null_data_variant() -> Result<()> {
    let kp = SampiKeyPair::new();
    let _ = kp.new_sampi().build(SampiData::Null)?;
    Ok(())
}

#[test]
fn test_to_and_from_bytes_with_additional_bytes() -> Result<()> {
    let kp = SampiKeyPair::new();
    let data = SampiData::String("Hello, World".to_string());
    let s = kp.new_sampi().build(data.clone())?;
    assert_eq!(s.data, data);

    let mut bytes = s.to_bytes();
    let original_bytes_length = bytes.len();
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    assert_eq!(
        Sampi::from_bytes(&bytes)?.to_bytes()[2..],
        bytes[2..original_bytes_length]
    );
    let s_from_bytes = Sampi::from_bytes(&bytes)?;
    assert_eq!(s.data, s_from_bytes.data);
    Ok(())
}

#[test]
fn test_to_and_from_base64() -> Result<()> {
    let kp = SampiKeyPair::new();
    let data = SampiData::String("Hello, World".to_string());
    let s = kp.new_sampi().build(data.clone())?;
    assert_eq!(s.data, data);
    assert_eq!(s.data.human_readable(), "Hello, World".to_string());
    assert_eq!(s.data.variant_name(), "String");

    let data = SampiData::JSON("{'a': 5}".to_string());
    let s = kp.new_sampi().build(data.clone())?;
    assert_eq!(s.data, data);
    assert_eq!(s.data.human_readable(), "{'a': 5}".to_string());
    assert_eq!(s.data.variant_name(), "JSON");

    let base64 = s.to_base64();
    assert_eq!(Sampi::from_base64(&base64)?.to_base64()[6..], base64[6..]);
    Ok(())
}

#[test]
fn test_to_and_from_hex() -> Result<()> {
    let kp = SampiKeyPair::new();
    let data = SampiData::String("Hello, World".to_string());
    let s = kp.new_sampi().build(data.clone())?;
    assert_eq!(s.data, data);

    let hex = s.to_hex();
    assert_eq!(Sampi::from_hex(&hex)?.to_hex()[4..], hex[4..]);
    Ok(())
}

#[test]
fn test_data_sizes() -> Result<()> {
    let kp = SampiKeyPair::new();
    assert!(kp.new_sampi().build(SampiData::U8Vec(vec![])).is_ok());
    assert!(kp.new_sampi().build(SampiData::U8Vec(vec![0; 900])).is_ok());
    assert_eq!(
        kp.new_sampi()
            .build(SampiData::U8Vec(vec![0; 900]))?
            .to_bytes()
            .len(),
        1024
    );
    assert!(kp
        .new_sampi()
        .build(SampiData::U8Vec(vec![0; 901]))
        .is_err());
    Ok(())
}

#[test]
fn test_pow() -> Result<()> {
    let kp = SampiKeyPair::new();
    let s = kp
        .new_sampi()
        .with_pow(20)
        .build(SampiData::U8Vec(vec![]))?;
    assert!(s.get_pow_score() >= 20);
    let base64 = s.to_base64();
    let s_2 = Sampi::from_base64(&base64)?;
    assert!(s_2.get_pow_score() >= 20);
    Ok(())
}

#[test]
fn test_one_thread_pow() -> Result<()> {
    let kp = SampiKeyPair::new();
    let s = kp
        .new_sampi()
        .with_pow(20)
        .with_pow_threads(1)
        .build(SampiData::U8Vec(vec![]))?;
    assert!(s.get_pow_score() >= 20);
    let base64 = s.to_base64();
    let s_2 = Sampi::from_base64(&base64)?;
    assert!(s_2.get_pow_score() >= 20);
    Ok(())
}

#[test]
fn test_from_str() -> Result<()> {
    let kp = SampiKeyPair::new();
    let s = kp.new_sampi().build(SampiData::U8Vec(vec![1, 2, 3]))?;
    let base64 = s.to_base64();
    let hex = s.to_hex();

    assert_eq!(Sampi::from_str(&base64)?.data, Sampi::from_str(&hex)?.data);
    Ok(())
}

#[test]
fn test_nesting() -> Result<()> {
    let kp = SampiKeyPair::new();
    let s_1 = kp.new_sampi().build(SampiData::U8Vec(vec![1, 2, 3]))?;
    let s_2 = kp.new_sampi().build(SampiData::U8Vec(s_1.to_bytes()))?;
    if let SampiData::U8Vec(bytes) = s_2.data {
        let s_3 = Sampi::from_bytes(&bytes)?;
        assert_eq!(s_1.data, s_3.data);
        assert_eq!(s_1.unix_time, s_3.unix_time);
        assert_eq!(s_1.get_hash(), s_3.get_hash());
        assert_eq!(s_3.data, SampiData::U8Vec(vec![1, 2, 3]));
    }

    Ok(())
}

#[test]
fn test_embedded() -> Result<()> {
    let kp = SampiKeyPair::new();
    let s_1 = kp.new_sampi().build(SampiData::U8Vec(vec![1, 2, 3]))?;
    let s_2 = kp
        .new_sampi()
        .build(SampiData::Sampi(Box::new(s_1.clone())))?;
    assert_eq!(SampiData::Sampi(Box::new(s_1.clone())), s_2.data);

    let s_3 = Sampi::from_base64(&s_2.to_base64())?;
    assert_eq!(SampiData::Sampi(Box::new(s_1)), s_3.data);

    Ok(())
}

#[test]
fn test_bincode_storage() -> Result<()> {
    let kp = SampiKeyPair::new();
    let v = (1, 2.0, 'a');
    let bincoded = bincode::serialize(&v)?;

    let s_1 = kp.new_sampi().build(SampiData::U8Vec(bincoded))?;
    let s_2 = Sampi::from_hex(&s_1.to_hex())?;

    if let SampiData::U8Vec(bytes) = s_2.data {
        let decoded_v = bincode::deserialize(&bytes)?;
        assert_eq!(v, decoded_v);
    }

    Ok(())
}

#[test]
fn test_ordering() -> Result<()> {
    let kp = SampiKeyPair::new();
    let mut sampis: Vec<_> = vec![5, 4, 3, 2, 1]
        .into_iter()
        .map(|i| {
            kp.new_sampi()
                .with_unix_time(i)
                .build(SampiData::U8Vec(vec![]))
                .unwrap()
        })
        .collect();
    assert_eq!(sampis[0].unix_time, 5);
    sampis.sort();
    assert_eq!(
        sampis.iter().map(|s| s.unix_time).collect::<Vec<_>>(),
        (1..=5).collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
fn test_filtering() -> Result<()> {
    let kp = SampiKeyPair::new();
    let sampis: Vec<_> = vec![5, 4, 3, 2, 1]
        .into_iter()
        .map(|i| {
            kp.new_sampi()
                .with_unix_time(i)
                .build(SampiData::Bytes(vec![]))
                .unwrap()
        })
        .collect();

    let mut filter = SampiFilter::new();
    filter.maximum_unix_time = Some(3);
    filter.data_variant = Some("Bytes".to_string());

    assert_eq!(sampis.into_iter().filter(|s| filter.matches(s)).count(), 3);
    Ok(())
}

#[test]
fn test_raptor_stream() -> Result<()> {
    let mut data: Vec<u8> = vec![0; 256 * 1024];
    for i in 0..data.len() {
        data[i] = rand::thread_rng().gen();
    }

    let stream_id = 723232;
    let mut stream = SampiRaptorStream::new();
    assert_eq!(stream.stream_id, None);
    assert_eq!(stream.public_key, None);
    let kp = SampiKeyPair::new();

    let mut new_data = Vec::new();

    for x in kp.new_sampi().build_raptor_stream(&data[..], stream_id) {
        for s in x {
            stream.insert(s);
        }

        if let Some(x) = stream.next() {
            new_data.extend_from_slice(&x);
        }
    }

    assert_eq!(stream.next(), None);
    assert_eq!(stream.stream_id, Some(stream_id));
    assert_eq!(stream.public_key, Some(kp.public_key()));
    assert!(data == new_data);
    Ok(())
}
