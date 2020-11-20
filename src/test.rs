use super::*;
use crate::SampiData;

use anyhow::Error;

#[test]
fn test_to_and_from_bytes() -> Result<(), Error> {
    let kp = SampiKeyPair::new();
    let data = SampiData::String("Hello, World".to_string());
    let s = kp.new_sampi().build(vec![data.clone()])?;
    assert_eq!(s.data, vec![data]);

    let bytes = s.to_bytes();
    let derialized_s = Sampi::from_bytes(&bytes)?;
    assert_eq!(derialized_s.to_bytes(), bytes);
    Ok(())
}

#[test]
fn test_from_str_parse() -> Result<(), Error> {
    let kp = SampiKeyPair::new();
    let data = SampiData::String("Hello, World".to_string());
    let s = kp.new_sampi().build(vec![data.clone()])?;
    assert_eq!(s.data, vec![data]);

    let s_2: Sampi = s.to_base64().parse()?;
    assert_eq!(s.data, s_2.data);
    Ok(())
}

#[test]
fn test_null_data_variant() -> Result<(), Error> {
    let kp = SampiKeyPair::new();
    assert!(kp.new_sampi().build(vec![SampiData::Null]).is_ok());
    Ok(())
}

#[test]
fn test_max_data_size() -> Result<(), Error> {
    let kp = SampiKeyPair::new();
    for i in 0..=1000 {
        let data = "x".repeat(i);
        let s = kp
            .new_sampi()
            .with_unix_time(4611686018427387904)
            .with_metadata(SampiMetadata::CounterAndBytes((
                2147483648,
                [1, 2, 3, 4, 5, 6],
            )))
            .build(vec![SampiData::String(data.clone())]);
        println!("i: {} - {}", i, s.is_err());
        if i > 900 {
            assert!(s.is_err());
        } else {
            assert!(s.is_ok());
            assert!(s.unwrap().to_bytes().len() - data.len() <= 124);
        }
    }
    Ok(())
}

#[test]
fn test_overhead() -> Result<(), Error> {
    let kp = SampiKeyPair::new();
    let data = "Hello, World".to_string();
    let s = kp
        .new_sampi()
        .with_unix_time(4611686018427387904)
        .with_metadata(SampiMetadata::CounterAndBytes((
            2147483648,
            [1, 2, 3, 4, 5, 6],
        )))
        .build(vec![SampiData::String(data.clone())])?;
    assert!(s.to_bytes().len() <= 1024);
    assert!(s.to_bytes().len() - data.len() <= 124);
    Ok(())
}

#[test]
fn test_to_and_from_bytes_with_additional_bytes() -> Result<(), Error> {
    let kp = SampiKeyPair::new();
    let data = SampiData::String("Hello, World".to_string());
    let s = kp.new_sampi().build(vec![data.clone()])?;
    assert_eq!(s.data, vec![data]);

    let mut bytes = s.to_bytes();
    let original_bytes_length = bytes.len();
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    assert_eq!(
        &Sampi::from_bytes(&bytes)?.to_bytes()[..],
        &bytes[..original_bytes_length]
    );
    let s_from_bytes = Sampi::from_bytes(&bytes)?;
    assert_eq!(s.data, s_from_bytes.data);
    Ok(())
}

#[test]
fn test_to_and_from_base64() -> Result<(), Error> {
    let kp = SampiKeyPair::new();
    let data = SampiData::String("Hello, World".to_string());
    let s = kp.new_sampi().build(vec![data.clone()])?;
    assert_eq!(s.data, vec![data]);
    assert_eq!(
        s.data.first().unwrap().human_readable(),
        "Hello, World".to_string()
    );
    assert_eq!(s.data.first().unwrap().variant_name(), "String");
    assert_eq!(s.data.first().unwrap().variant(), 15);

    let data = SampiData::String("{'a': 5}".to_string());
    let s = kp.new_sampi().build(vec![data.clone()])?;
    assert_eq!(s.data, vec![data]);
    assert_eq!(
        s.data.first().unwrap().human_readable(),
        "{'a': 5}".to_string()
    );
    assert_eq!(s.data.first().unwrap().variant_name(), "String");
    assert_eq!(s.data.first().unwrap().variant(), 15);

    let base64 = s.to_base64();
    assert_eq!(Sampi::from_base64(&base64)?.to_base64(), base64);
    Ok(())
}

#[test]
fn test_to_and_from_hex() -> Result<(), Error> {
    let kp = SampiKeyPair::new();
    let data = SampiData::String("Hello, World".to_string());
    let s = kp.new_sampi().build(vec![data.clone()])?;
    assert_eq!(s.data, vec![data]);

    let hex = s.to_hex();
    assert_eq!(Sampi::from_hex(&hex)?.to_hex(), hex);
    Ok(())
}

#[test]
fn test_to_and_from_base32() -> Result<(), Error> {
    let kp = SampiKeyPair::new();
    let data = SampiData::String("Hello, World".to_string());
    let s = kp.new_sampi().build(vec![data.clone()])?;
    assert_eq!(s.data, vec![data]);
    assert_eq!(
        s.data.first().unwrap().human_readable(),
        "Hello, World".to_string()
    );
    assert_eq!(s.data.first().unwrap().variant_name(), "String");
    assert_eq!(s.data.first().unwrap().variant(), 15);

    let data = SampiData::String("{'a': 5}".to_string());
    let s = kp.new_sampi().build(vec![data.clone()])?;
    assert_eq!(s.data, vec![data]);
    assert_eq!(
        s.data.first().unwrap().human_readable(),
        "{'a': 5}".to_string()
    );
    assert_eq!(s.data.first().unwrap().variant_name(), "String");
    assert_eq!(s.data.first().unwrap().variant(), 15);

    let base32 = s.to_base32();
    assert_eq!(Sampi::from_base32(&base32)?.to_base32(), base32);
    Ok(())
}

#[test]
fn test_to_and_from_base58() -> Result<(), Error> {
    let kp = SampiKeyPair::new();
    let data = SampiData::String("Hello, World".to_string());
    let s = kp.new_sampi().build(vec![data.clone()])?;
    assert_eq!(s.data, vec![data]);
    assert_eq!(
        s.data.first().unwrap().human_readable(),
        "Hello, World".to_string()
    );
    assert_eq!(s.data.first().unwrap().variant_name(), "String");
    assert_eq!(s.data.first().unwrap().variant(), 15);

    let data = SampiData::String("{'a': 5}".to_string());
    let s = kp.new_sampi().build(vec![data.clone()])?;
    assert_eq!(s.data, vec![data]);
    assert_eq!(
        s.data.first().unwrap().human_readable(),
        "{'a': 5}".to_string()
    );
    assert_eq!(s.data.first().unwrap().variant_name(), "String");
    assert_eq!(s.data.first().unwrap().variant(), 15);

    let base58 = s.to_base58();
    assert_eq!(Sampi::from_base58(&base58)?.to_base58(), base58);
    Ok(())
}

#[test]
fn test_pow() -> Result<(), Error> {
    let kp = SampiKeyPair::new();
    let s = kp.new_sampi().with_pow(20).build(vec![])?;
    assert!(s.get_pow_score() >= 20);
    let base64 = s.to_base64();
    let s_2 = Sampi::from_base64(&base64)?;
    assert!(s_2.get_pow_score() >= 20);
    Ok(())
}

#[test]
fn test_one_thread_pow() -> Result<(), Error> {
    let kp = SampiKeyPair::new();
    let s = kp
        .new_sampi()
        .with_pow(20)
        .with_pow_threads(1)
        .build(vec![])?;
    assert!(s.get_pow_score() >= 20);
    let base64 = s.to_base64();
    let s_2 = Sampi::from_base64(&base64)?;
    assert!(s_2.get_pow_score() >= 20);
    Ok(())
}

#[test]
fn test_from_str() -> Result<(), Error> {
    let kp = SampiKeyPair::new();
    let s = kp
        .new_sampi()
        .build(vec![SampiData::Bytes(vec![1, 2, 3])])?;
    let base64 = s.to_base64();
    let hex = s.to_hex();

    assert_eq!(Sampi::from_str(&base64)?.data, Sampi::from_str(&hex)?.data);
    Ok(())
}

#[test]
fn test_nesting() -> Result<(), Error> {
    let kp = SampiKeyPair::new();
    let s_1 = kp
        .new_sampi()
        .build(vec![SampiData::Bytes(vec![1, 2, 3])])?;
    let s_2 = kp
        .new_sampi()
        .build(vec![SampiData::Bytes(s_1.to_bytes())])?;
    if let Some(SampiData::Bytes(bytes)) = s_2.data.first() {
        let s_3 = Sampi::from_bytes(&bytes)?;
        assert_eq!(s_1.data, s_3.data);
        assert_eq!(s_1.unix_time, s_3.unix_time);
        assert_eq!(s_1.get_hash(), s_3.get_hash());
        assert_eq!(s_3.data, vec![SampiData::Bytes(vec![1, 2, 3])]);
    }

    Ok(())
}

#[test]
fn test_embedded() -> Result<(), Error> {
    let kp = SampiKeyPair::new();
    let s_1 = kp
        .new_sampi()
        .build(vec![SampiData::Bytes(vec![1, 2, 3])])?;
    let s_2 = kp
        .new_sampi()
        .build(vec![SampiData::Sampi(Box::new(s_1.clone()))])?;
    assert_eq!(vec![SampiData::Sampi(Box::new(s_1.clone()))], s_2.data);

    let s_3 = Sampi::from_base64(&s_2.to_base64())?;
    assert_eq!(vec![SampiData::Sampi(Box::new(s_1))], s_3.data);

    Ok(())
}

#[test]
fn test_bincode_storage() -> Result<(), Error> {
    let kp = SampiKeyPair::new();
    let v = (1, 2.0, 'a');
    let bincoded = bincode::serialize(&v)?;

    let s_1 = kp.new_sampi().build(vec![SampiData::Bytes(bincoded)])?;
    let s_2 = Sampi::from_hex(&s_1.to_hex())?;

    if let Some(SampiData::Bytes(bytes)) = s_2.data.first() {
        let decoded_v = bincode::deserialize(&bytes)?;
        assert_eq!(v, decoded_v);
    }

    Ok(())
}

#[test]
fn test_ordering() -> Result<(), Error> {
    let kp = SampiKeyPair::new();
    let mut sampis: Vec<_> = vec![5, 4, 3, 2, 1]
        .into_iter()
        .map(|i| kp.new_sampi().with_unix_time(i).build(vec![]).unwrap())
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
fn test_filtering() -> Result<(), Error> {
    let kp = SampiKeyPair::new();
    let sampis: Vec<_> = vec![5, 4, 3, 2, 1]
        .into_iter()
        .filter_map(|i| {
            kp.new_sampi()
                .with_unix_time(i)
                .build(vec![SampiData::StringPair((
                    "a".to_string(),
                    "b".to_string(),
                ))])
                .ok()
        })
        .collect();

    let mut filter = SampiFilter::new();
    filter.maximum_unix_time = Some(3);
    filter.data_variant = Some(16);

    let current_unix_time = get_unix_time_millis();
    assert_eq!(
        sampis
            .into_iter()
            .filter(|s| filter.matches(s, current_unix_time))
            .count(),
        3
    );
    Ok(())
}

#[test]
fn test_maximum_age_filtering() -> Result<(), Error> {
    #[cfg(any(not(target_arch = "wasm32"), target_os = "wasi"))]
    let unix_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    let unix_time = Date::now() as i64;

    let kp = SampiKeyPair::new();
    let sampis: Vec<_> = vec![10000, 5000, 3000, 2000, 1000]
        .into_iter()
        .filter_map(|i| {
            kp.new_sampi()
                .with_unix_time(unix_time - i)
                .build(vec![])
                .ok()
        })
        .collect();

    let mut filter = SampiFilter::new();
    filter.maximum_unix_time_age = Some(3500);

    let current_unix_time = get_unix_time_millis();
    dbg!(current_unix_time);
    assert_eq!(
        sampis
            .into_iter()
            .filter(|s| filter.matches(s, current_unix_time))
            .count(),
        3
    );
    Ok(())
}

#[test]
fn test_to_and_from_bytes_with_corruption() -> Result<(), Error> {
    let kp = SampiKeyPair::new();
    let data = SampiData::String("Hello, World".to_string());
    let s = kp.new_sampi().build(vec![data.clone()])?;
    assert_eq!(s.data, vec![data]);
    assert_eq!(
        s.data.first().unwrap().human_readable(),
        "Hello, World".to_string()
    );
    assert_eq!(s.data.first().unwrap().variant_name(), "String");
    assert_eq!(s.data.first().unwrap().variant(), 15);

    let bytes = s.to_bytes();

    for _ in 0..100 {
        for i in 0..bytes.len() {
            dbg!(i);
            let mut mutated_bytes = bytes.clone();
            mutated_bytes[i] = rand::thread_rng().gen();

            if &mutated_bytes == &bytes {
                continue;
            }

            assert!(Sampi::from_bytes(&mutated_bytes).is_err())
        }
    }
    Ok(())
}

#[test]
fn test_nonce_not_mutatable() -> Result<(), Error> {
    let kp = SampiKeyPair::new();
    let data = SampiData::String("Hello, World".to_string());
    let mut s = kp.new_sampi().with_pow(20).build(vec![data])?;

    assert!(s.get_pow_score() >= 20);

    for _ in 0..50 {
        s.nonce += 1;
        assert!(Sampi::from_bytes(&s.to_bytes()).is_err());
    }

    Ok(())
}

#[test]
fn test_hex_random_mutation() -> Result<(), Error> {
    let kp = SampiKeyPair::new();
    let data = SampiData::String("Hello, World".to_string());
    let s = kp.new_sampi().build(vec![data])?;
    let original_string = s.to_hex().to_ascii_lowercase();
    let bytes = original_string.clone().into_bytes();

    for _ in 0..100 {
        for i in 0..bytes.len() {
            let mut mutated_bytes = bytes.clone();
            mutated_bytes[i] = rand::thread_rng().gen();

            if let Ok(mutated_string) =
                std::str::from_utf8(&mutated_bytes).map(|m| m.to_ascii_lowercase())
            {
                if mutated_string == original_string {
                    continue;
                }

                assert!(Sampi::from_hex(&mutated_string).is_err());
            }
        }
    }
    Ok(())
}

#[test]
fn test_base32_random_mutation() -> Result<(), Error> {
    let kp = SampiKeyPair::new();
    let data = SampiData::String("Hello, World".to_string());
    let s = kp.new_sampi().build(vec![data])?;
    let original_string = s.to_base32().to_ascii_lowercase();
    let bytes = original_string.clone().into_bytes();

    for _ in 0..100 {
        for i in 0..bytes.len() {
            let mut mutated_bytes = bytes.clone();
            mutated_bytes[i] = rand::thread_rng().gen();

            if let Ok(mutated_string) =
                std::str::from_utf8(&mutated_bytes).map(|m| m.to_ascii_lowercase())
            {
                if mutated_string == original_string {
                    continue;
                }

                if let Ok(new_s) = Sampi::from_base32(&mutated_string) {
                    assert!(s.to_bytes() == new_s.to_bytes());
                }
            }
        }
    }
    Ok(())
}

#[test]
fn test_base58_random_mutation() -> Result<(), Error> {
    let kp = SampiKeyPair::new();
    let data = SampiData::String("Hello, World".to_string());
    let s = kp.new_sampi().build(vec![data])?;

    let bytes = s.to_base58().into_bytes();

    for _ in 0..100 {
        for i in 0..bytes.len() {
            let mut mutated_bytes = bytes.clone();
            mutated_bytes[i] = rand::thread_rng().gen();

            if &mutated_bytes == &bytes {
                continue;
            }

            assert!(std::str::from_utf8(&mutated_bytes)
                .map_err(|_| SampiError::ValidationError)
                .and_then(|str| Sampi::from_base58(str))
                .is_err());
        }
    }

    Ok(())
}

#[test]
fn test_base64_random_mutation() -> Result<(), Error> {
    let kp = SampiKeyPair::new();
    let data = SampiData::String("Hello, World".to_string());
    let s = kp.new_sampi().build(vec![data])?;
    let bytes = s.to_base64().into_bytes();

    for _ in 0..100 {
        for i in 0..bytes.len() {
            let mut mutated_bytes = bytes.clone();
            mutated_bytes[i] = rand::thread_rng().gen();

            if &mutated_bytes == &bytes {
                continue;
            }

            if let Ok(new_s) = std::str::from_utf8(&mutated_bytes)
                .map_err(|_| SampiError::ValidationError)
                .and_then(|str| Sampi::from_base64(str))
            {
                assert!(s.to_bytes() == new_s.to_bytes());
            }
        }
    }
    Ok(())
}

#[test]
fn test_bytes_random_mutation() -> Result<(), Error> {
    let kp = SampiKeyPair::new();
    let data = SampiData::String("Hello, World".to_string());
    let s = kp.new_sampi().build(vec![data])?;
    let bytes = s.to_bytes();
    for _ in 0..100 {
        for i in 0..bytes.len() {
            let mut mutated_bytes = bytes.clone();
            mutated_bytes[i] = rand::thread_rng().gen();

            if &mutated_bytes == &bytes {
                continue;
            }

            assert!(Sampi::from_bytes(&mutated_bytes).is_err());
        }
    }
    Ok(())
}
