use std::time::Instant;

use sampi::{Result, SampiData, SampiKeyPair};

fn main() -> Result<()> {
    let kp = SampiKeyPair::new();

    let data = SampiData::String("Hello World! 你好!".to_string());
    for i in 0..=200 {
        let mut milliseconds = Vec::new();
        for _ in 1..=100 {
            let now = Instant::now();
            let _s = kp.new_sampi().with_pow(i).build(data.clone())?;
            let elapsed = now.elapsed();
            milliseconds.push((elapsed.as_secs() * 1000) + elapsed.subsec_millis() as u64);
        }
        let sum: u64 = milliseconds.iter().sum();
        println!("{},{}", i, sum / milliseconds.len() as u64);
    }

    Ok(())
}
