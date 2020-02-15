use sampi::{Result, Sampi, SampiData, SampiKeyPair};

fn main() -> Result<()> {
    let kp: SampiKeyPair = Default::default();

    let data = "Hello World! 你好!".to_string();
    let sampi = kp.new_sampi().build(SampiData::String(data))?;

    println!("Sampi size in bytes: {}", sampi.to_bytes().len());
    let base64_string = sampi.to_base64();
    println!(
        "base64: {} - {} characters",
        &base64_string,
        &base64_string.len()
    );

    let deserialized_sampi = Sampi::from_base64(&base64_string)?;
    println!("Deserialized data: {:?}", deserialized_sampi.data);

    dbg!(deserialized_sampi.data.to_string());
    Ok(())
}
