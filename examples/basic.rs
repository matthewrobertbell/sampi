use sampi::{Sampi, SampiData, SampiKeyPair, SampiMetadata};

fn main() -> anyhow::Result<()> {
    let kp = SampiKeyPair::new();

    let data = "x".repeat(900);
    let data_length = data.len();

    let sampi = kp
        .new_sampi()
        .with_metadata(SampiMetadata::CounterAndBytes((1073741824, [77; 6])))
        .build(vec![SampiData::String(data)])?;

    println!("Sampi size in bytes: {}", sampi.to_bytes().len());
    println!("Overhead: {}", sampi.to_bytes().len() - data_length);
    let base64_string = sampi.to_base64();
    println!(
        "base64: {} - {} characters",
        &base64_string,
        &base64_string.len()
    );

    let deserialized_sampi = Sampi::from_base64(&base64_string)?;
    println!(
        "Deserialized data: {:?}",
        deserialized_sampi.data.first().unwrap().human_readable()
    );
    println!(
        "Data variant: {}",
        deserialized_sampi.data.first().unwrap().variant_name()
    );

    let bytes = sampi.to_bytes().repeat(5);
    dbg!(bytes.len());

    dbg!(Sampi::from_bytes_iterator(&bytes).collect::<Vec<_>>());

    Ok(())
}
