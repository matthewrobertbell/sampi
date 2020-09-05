use std::io::{self, Read};
use std::str::FromStr;

use structopt::StructOpt;

use sampi::SampiKeyPair;

use qrcodegen::{QrCode, QrCodeEcc};

#[derive(Debug)]
struct HexData64(Vec<u8>);

impl FromStr for HexData64 {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 64 {
            return Err(Self::Err::InvalidStringLength);
        }
        hex::decode(s).map(HexData64)
    }
}

#[derive(Debug)]
struct HexData32(Vec<u8>);

impl FromStr for HexData32 {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 32 {
            return Err(Self::Err::InvalidStringLength);
        }
        hex::decode(s).map(HexData32)
    }
}

#[derive(Debug)]
enum OutputType {
    Base16,
    Base32,
    Base58,
    Base64,
    QRCode,
}

impl FromStr for OutputType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Hex" => Ok(OutputType::Base16),
            "Base16" => Ok(OutputType::Base16),
            "Base32" => Ok(OutputType::Base32),
            "Base58" => Ok(OutputType::Base58),
            "Base64" => Ok(OutputType::Base64),
            "hex" => Ok(OutputType::Base16),
            "base16" => Ok(OutputType::Base16),
            "base32" => Ok(OutputType::Base32),
            "base58" => Ok(OutputType::Base58),
            "base64" => Ok(OutputType::Base64),
            "qr" => Ok(OutputType::QRCode),
            "qrcode" => Ok(OutputType::QRCode),
            _ => Err("Not a valid output type".to_string()),
        }
    }
}

#[derive(StructOpt, Debug)]
#[structopt(name = "Sampi")]
enum Opt {
    #[structopt(name = "keys")]
    Keys {},

    #[structopt(name = "decode")]
    Decode {
        #[structopt(short, long)]
        verbose: bool,

        #[structopt(short, long)]
        acceptable_public_keys: Vec<HexData64>,
    },

    #[structopt(name = "encode")]
    Encode {
        /// Saved key to use. If not set, a new key is generated and saved with this name
        #[structopt(short, long)]
        key: Option<String>,

        /// Use a random unix time, rather than the current unix time
        #[structopt(long)]
        random_unix_time: bool,

        /// Set a specific unix time, rather than the current unix time
        #[structopt(short, long)]
        unix_time: Option<i64>,

        /// Minimum Proof of Work score to generate
        #[structopt(short, long)]
        pow: Option<u8>,

        /// Number of threads to use for Proof of Work, default is the number of processor cores
        #[structopt(long)]
        pow_threads: Option<u64>,

        #[structopt(long)]
        output_type: Option<OutputType>,
    },
}

fn main() -> sampi::Result<()> {
    match Opt::from_args() {
        Opt::Decode {
            verbose,
            acceptable_public_keys,
        } => {
            let mut data = String::new();
            io::stdin().read_to_string(&mut data)?;
            match sampi::Sampi::from_str(&data.trim()) {
                Ok(s) => {
                    if !acceptable_public_keys.is_empty()
                        && !acceptable_public_keys
                            .iter()
                            .any(|k| hex::encode(&k.0) == s.get_public_key_as_hex())
                    {
                        return Err("Not an acceptable public key".into());
                    }
                    if verbose {
                        println!("Public Key: {}", s.get_public_key_as_hex());
                        println!("UNIX Time: {}", s.unix_time);
                        println!("POW Score: {}", s.get_pow_score());
                        println!("Data Variant Name: {}", s.data.variant_name());
                        println!("Data: {}", s.data.human_readable());
                        println!("Metatdata: {:?}", s.metadata);
                    } else {
                        print!("{}", s.data.human_readable());
                    }
                }
                Err(e) => println!("{}", e),
            }
        }
        Opt::Keys {} => {
            for (name, skp) in sampi::SampiKeyPair::list_keys()? {
                println!("{} - {}", skp.public_key_as_hex(), name);
            }
        }
        Opt::Encode {
            key,
            random_unix_time,
            unix_time,
            pow,
            pow_threads,
            output_type,
        } => {
            let kp = match key {
                None => SampiKeyPair::new(),
                Some(key) => match sampi::SampiKeyPair::load_from_file(&key) {
                    Ok(kp) => kp,
                    Err(_) => {
                        let kp = SampiKeyPair::new();
                        kp.save_to_file(&key)?;
                        kp
                    }
                },
            };

            let mut data = String::new();
            io::stdin().read_to_string(&mut data)?;

            let mut builder = kp.new_sampi();

            if random_unix_time {
                builder = builder.with_random_unix_time();
            }
            if let Some(unix_time) = unix_time {
                builder = builder.with_unix_time(unix_time);
            }
            if let Some(pow) = pow {
                builder = builder.with_pow(pow);
            }
            if let Some(pow_threads) = pow_threads {
                builder = builder.with_pow_threads(pow_threads);
            }

            let s = builder.build(sampi::SampiData::String(data.trim().to_string()))?;

            match output_type {
                None | Some(OutputType::Base64) => {
                    println!("{}", s.to_base64());
                }
                Some(OutputType::Base58) => {
                    println!("{}", s.to_base58());
                }
                Some(OutputType::Base32) => {
                    println!("{}", s.to_base32());
                }
                Some(OutputType::Base16) => {
                    println!("{}", s.to_hex());
                }
                Some(OutputType::QRCode) => {
                    let qr_code = QrCode::encode_text(&s.to_base64(), QrCodeEcc::Medium)?;
                    let border: i32 = 4;
                    for y in -border..qr_code.size() + border {
                        for x in -border..qr_code.size() + border {
                            let c: char = if qr_code.get_module(x, y) { ' ' } else { '█' };
                            print!("{0}{0}", c);
                        }
                        println!();
                    }
                    println!();
                }
            }
        }
    }
    Ok(())
}
