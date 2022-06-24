use sampi::{Sampi, SampiKeyPair};
use std::convert::TryInto;

fn main() -> anyhow::Result<()> {
    let kp = SampiKeyPair::new();

    let data = "abcd efgh 1234 5678".to_string();
    let data_length = data.len();

    let sampi = kp.new_sampi().with_pow(20).build(vec![
        "xyz".into(),
        data.into(),
        1234u64.into(),
        ("a", "b").into(),
    ])?;

    dbg!(&sampi);

    let bytes = sampi.to_bytes();

    println!("Sampi size in bytes: {}", bytes.len());
    println!("Overhead: {}", bytes.len() - data_length);
    let base64_string = sampi.to_base64();
    println!(
        "base64: {} - {} characters",
        &base64_string,
        &base64_string.len()
    );

    let deserialized_sampi: Sampi = bytes.as_slice().try_into()?;
    dbg!(&deserialized_sampi);

    let base58_string = sampi.to_base58();
    println!(
        "base58: {} - {} characters",
        &base58_string,
        &base58_string.len()
    );

    let deserialized_sampi = Sampi::from_base64(&base64_string)?;
    println!(
        "Deserialized data: {:?}",
        deserialized_sampi.data().first().unwrap().human_readable()
    );
    println!(
        "Data variant: {}",
        deserialized_sampi.data().first().unwrap().variant_name()
    );

    let bytes = sampi.to_bytes().repeat(5);
    dbg!(bytes.len());

    dbg!(Sampi::from_bytes_iterator(&bytes).collect::<Vec<_>>());

    Ok(())
}
