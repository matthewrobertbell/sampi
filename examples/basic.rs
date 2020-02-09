use sampi::{Result, Sampi, SampiKeyPair};

fn main() -> Result<()> {
    let kp = SampiKeyPair::new();

    let data = "Hello World! 你好!";
    let sampi = kp.new_sampi().build(data)?;

    println!("Sampi size in bytes: {}", sampi.to_bytes().len());
    let base64_string = sampi.to_base64();
    println!(
        "base64: {} - {} characters",
        &base64_string,
        &base64_string.len()
    );

    let deserialized_sampi = Sampi::from_base64(&base64_string)?;
    println!(
        "Deserialized data as a string: '{}'",
        deserialized_sampi.data_as_string().unwrap()
    );
    Ok(())
}
