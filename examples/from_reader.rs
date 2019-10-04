use sampi::{Result, SampiKeyPair};

use std::fs::File;

fn main() -> Result<()> {
    let f = File::open("LICENSE-APACHE")?;
    let kp = SampiKeyPair::new()?;
    for s in kp.new_sampi().with_random_unix_time().build_from_reader(f) {
        dbg!(s.data_as_string()?);
        dbg!(s.to_base64());
    }

    Ok(())
}
