use std::io::{self, Read};
use std::str::FromStr;

use hex;
use structopt::StructOpt;

use sampi;
use sampi::SampiKeyPair;

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

        /// Output as hex, instead of as a string
        #[structopt(long)]
        hex: bool,
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
        unix_time: Option<u64>,

        /// Minimum Proof of Work score to generate
        #[structopt(short, long)]
        pow: Option<u8>,

        /// Number of threads to use for Proof of Work, default is the number of processor cores
        #[structopt(long)]
        pow_threads: Option<u64>,

        /// Output as hex, instead of the default base64
        #[structopt(long)]
        hex: bool,
    },
}

fn main() -> sampi::Result<()> {
    match Opt::from_args() {
        Opt::Decode {
            verbose,
            acceptable_public_keys,
            hex,
        } => {
            let mut data = String::new();
            io::stdin().read_to_string(&mut data)?;
            match sampi::Sampi::from_str(&data.trim()) {
                Ok(s) => {
                    if !acceptable_public_keys.is_empty()
                        && !acceptable_public_keys
                            .iter()
                            .any(|k| hex::encode(&k.0) == s.public_key_as_hex())
                    {
                        return Err("Not an acceptable public key".into());
                    }
                    if verbose {
                        println!("Public Key: {}", s.public_key_as_hex());
                        println!("UNIX Time: {}", s.unix_time);
                        println!("POW Score: {}", s.get_pow_score());
                    }
                    if hex {
                        print!("{}", &s.to_hex());
                    } else {
                        print!("{:?}", &s.data);
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
            hex,
        } => {
            let kp = match key {
                None => Default::default(),
                Some(key) => match sampi::SampiKeyPair::load_from_file(&key) {
                    Ok(kp) => kp,
                    Err(_) => {
                        let kp: SampiKeyPair = Default::default();
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

            if hex {
                println!("{}", s.to_hex());
            } else {
                println!("{}", s.to_base64());
            }
        }
    }
    Ok(())
}
