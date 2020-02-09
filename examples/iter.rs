use sampi::{Result, SampiKeyPair};

fn main() -> Result<()> {
    let kp = SampiKeyPair::new();

    let sampi_builder = kp.new_sampi().with_pow(10);

    let mut previous_hash = [0u8; 16];

    for i in 0..1000 {
        let s = sampi_builder
            .clone()
            .with_metadata(previous_hash)
            .build(i.to_string())?;
        println!("{}", i);
        println!("Sampi size in bytes: {}", s.to_bytes().len());
        let base64_string = s.to_base64();
        println!("base64: {}", &base64_string);
        println!("Previous hash: {:?}", previous_hash);
        println!("Current hash: {:?}", &s.get_hash_bytes()[..16]);
        previous_hash.copy_from_slice(&s.get_hash_bytes()[..16]);
        dbg!(s.get_pow_score());
    }
    Ok(())
}
