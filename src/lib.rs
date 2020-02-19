use std::env;
use std::error::Error;
use std::fmt;
use std::fs::{create_dir, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::string::ToString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;

#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};

use base64::decode_config as base64_decode_config;
use base64::encode_config as base64_encode_config;
use bincode::{deserialize, serialize};
use dirs;
use ed25519_dalek::{Keypair, PublicKey, Signature};
use glob::glob;
use hex;
use rand::Rng;
use rand_core::OsRng;
use serde_big_array::big_array;
use serde_derive::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

extern crate strum;
#[macro_use]
extern crate strum_macros;

#[cfg(target_arch = "wasm32")]
use js_sys::Date;

big_array! { BigArray; }

pub const MAX_DATA_LENGTH: usize = 912;
const SAMPI_OVERHEAD: usize = 112;

pub type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync + 'static>>;

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Display)]
pub enum SampiData {
    // No Data
    Null,
    // Vecs of primitive types
    U8Vec(Vec<u8>),
    U16Vec(Vec<u16>),
    U32Vec(Vec<u32>),
    U64Vec(Vec<u64>),
    U128Vec(Vec<u128>),
    I8Vec(Vec<i8>),
    I16Vec(Vec<i16>),
    I32Vec(Vec<i32>),
    I64Vec(Vec<i64>),
    I128Vec(Vec<i128>),
    F32Vec(Vec<f32>),
    F64Vec(Vec<f64>),
    BoolVec(Vec<bool>),
    CharVec(Vec<char>),

    // String aliases
    String(String),
    JSON(String),

    // Vec of String alises
    StringVec(Vec<String>),

    // Vec<u8> aliases
    Bytes(Vec<u8>),
    BSON(Vec<u8>),
    CBOR(Vec<u8>),

    // Sampi specific
    SampiFilter(SampiFilter),
    Sampi(Box<Sampi>),

    // Vecs of byte arrays
    Array8ByteVec(Vec<[u8; 8]>),
    Array16ByteVec(Vec<[u8; 16]>),
    Array32ByteVec(Vec<[u8; 32]>),
}

pub struct SampiKeyPair {
    keypair: Keypair,
}

impl Default for SampiKeyPair {
    fn default() -> Self {
        Self {
            keypair: Keypair::generate(&mut OsRng),
        }
    }
}

impl SampiKeyPair {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            keypair: Keypair::from_bytes(bytes)
                .map_err(|_| "Cannot read keypair from bytes".to_string())?,
        })
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        self.keypair.to_bytes()
    }

    pub fn public_key_as_hex(&self) -> String {
        hex::encode(&self.keypair.public)
    }

    pub fn public_key(&self) -> [u8; 32] {
        *self.keypair.public.as_bytes()
    }

    fn data_dir() -> Result<PathBuf> {
        let path = match env::var("SAMPI_KEYS_PATH") {
            Ok(env_path) => PathBuf::from(env_path),
            Err(_) => {
                let mut path = dirs::data_dir().ok_or("Can't find Data Dir")?;
                path.push("sampi");
                path
            }
        };

        if !&path.exists() {
            create_dir(&path)?;
        }
        Ok(path)
    }

    pub fn list_keys() -> Result<Vec<(String, SampiKeyPair)>> {
        let mut path = Self::data_dir()?;
        path.push("*.key");

        let keys: Vec<_> = glob(path.to_str().ok_or("Error")?)?
            .filter_map(|p| p.ok())
            .filter_map(|p| {
                p.file_stem()
                    .and_then(|p| p.to_os_string().into_string().ok())
            })
            .filter_map(|p| Self::load_from_file(&p).map(|kp| (p, kp)).ok())
            .collect();
        Ok(keys)
    }

    pub fn save_to_file(&self, name: &str) -> Result<()> {
        let bytes = self.to_bytes();

        let mut path = Self::data_dir()?;
        path.push(format!("{}.key", name));
        let mut writer = File::create(path)?;
        writer.write_all(&bytes)?;
        Ok(())
    }

    pub fn load_from_file(name: &str) -> Result<SampiKeyPair> {
        let mut path = Self::data_dir()?;
        path.push(format!("{}.key", name));

        let mut f = File::open(path)?;
        let mut bytes = vec![0u8; 64];
        f.read_exact(&mut bytes)?;
        Ok(SampiKeyPair::from_bytes(&bytes)?)
    }

    pub fn new_sampi(&self) -> SampiBuilder {
        SampiBuilder::new(&self)
    }
}

#[derive(Clone)]
pub struct SampiBuilder<'a> {
    min_pow_score: Option<u8>,
    ss_keypair: &'a SampiKeyPair,
    unix_time: Option<u64>,
    threads_count: u64,
}

impl<'a> SampiBuilder<'a> {
    fn new(ss_keypair: &'a SampiKeyPair) -> Self {
        SampiBuilder {
            min_pow_score: None,
            ss_keypair,
            unix_time: None,
            threads_count: 1,
        }
    }

    pub fn with_pow(mut self, min_pow_score: u8) -> Self {
        self.min_pow_score = Some(min_pow_score);
        self.threads_count = num_cpus::get() as u64;
        self
    }

    pub fn with_pow_threads(mut self, threads_count: u64) -> Self {
        self.threads_count = threads_count;
        self
    }

    pub fn with_unix_time(mut self, unix_time: u64) -> Self {
        self.unix_time = Some(unix_time);
        self
    }

    pub fn with_random_unix_time(mut self) -> Self {
        self.unix_time = Some(OsRng.gen_range(0, 2u64.pow(48) - 1));
        self
    }

    pub fn build(&self, data: SampiData) -> Result<Sampi> {
        Sampi::new(
            data,
            self.min_pow_score,
            &self.ss_keypair,
            self.unix_time,
            self.threads_count,
        )
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Sampi {
    pub data: SampiData,
    pub public_key: [u8; 32],
    pub unix_time: u64,
    #[serde(with = "BigArray")]
    signature: [u8; 64],
    nonce: u64,
}

impl Sampi {
    pub fn public_key_as_hex(&self) -> String {
        hex::encode(&self.public_key)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < SAMPI_OVERHEAD {
            return Err("Deserialization input data is too small".into());
        }

        let data_length: u16 = deserialize(&bytes[2..4])?;
        if data_length as usize > MAX_DATA_LENGTH {
            return Err("Data length is too large".into());
        }

        let mut new_bytes = (&bytes[..data_length as usize + SAMPI_OVERHEAD]).to_vec();
        new_bytes[2] = 0;
        new_bytes[3] = 0;

        deserialize(&new_bytes).map_err(|e| e.into())
    }

    fn serialize(&self) -> Vec<u8> {
        let mut serialized = serialize(&self).unwrap();
        let data_length = serialized.len() - SAMPI_OVERHEAD;
        let serialized_length = serialize(&(data_length as u16)).unwrap();
        serialized[2] = serialized_length[0];
        serialized[3] = serialized_length[1];
        serialized
    }

    fn validate(self, serialized_data: &[u8], min_pow_score: Option<u8>) -> Result<Self> {
        if serialized_data.len() > MAX_DATA_LENGTH + SAMPI_OVERHEAD {
            return Err("Data too large".into());
        }

        let signable_data = self.generate_signable_data();

        if let Some(min_pow_score) = min_pow_score {
            let pow_score = calculate_pow_score(&signable_data);

            if pow_score < min_pow_score {
                return Err("Hash too small".into());
            }
        }

        let public_key =
            PublicKey::from_bytes(&self.public_key).map_err(|_| "Validation Error".to_string())?;
        let signature =
            Signature::from_bytes(&self.signature).map_err(|_| "Validation Error".to_string())?;
        public_key
            .verify(&signable_data, &signature)
            .map_err(|_| "Validation Error".to_string())?;

        Ok(self)
    }

    /// Attempt to deserialize a Sampi object from a &str of base64
    pub fn from_base64(base64_string: &str) -> Result<Self> {
        let decoded = base64_decode_config(base64_string, base64::URL_SAFE)?;
        let s: Sampi = Self::deserialize(&decoded)?;
        s.validate(&decoded, None)
    }

    pub fn from_base64_with_pow_check(base64_string: &str, min_pow_score: u8) -> Result<Self> {
        let decoded = base64_decode_config(base64_string, base64::URL_SAFE)?;
        let s: Sampi = Self::deserialize(&decoded)?;
        s.validate(&decoded, Some(min_pow_score))
    }

    pub fn to_base64(&self) -> String {
        base64_encode_config(&self.serialize(), base64::URL_SAFE)
    }

    /// Attempt to deserialize a Sampi object from a &str of hex
    pub fn from_hex(hex_string: &str) -> Result<Self> {
        let decoded = hex::decode(hex_string)?;
        let s: Sampi = Self::deserialize(&decoded)?;
        s.validate(&decoded, None)
    }

    pub fn from_hex_with_pow_check(hex_string: &str, min_pow_score: u8) -> Result<Self> {
        let decoded = hex::decode(hex_string)?;
        let s: Sampi = Self::deserialize(&decoded)?;
        s.validate(&decoded, Some(min_pow_score))
    }

    /// Serialize this Sampi object to a hex string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.serialize())
    }

    /// Attempt to deserialize a Sampi object from a slice of bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let s: Sampi = Self::deserialize(&bytes)?;
        s.validate(&bytes, None)
    }

    pub fn from_bytes_with_pow_check(bytes: &[u8], min_pow_score: u8) -> Result<Self> {
        let s: Sampi = Self::deserialize(&bytes)?;
        s.validate(&bytes, Some(min_pow_score))
    }

    /// Serialize this Sampi object to a Vector of bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.serialize()
    }

    /// Attempt to deserialize from a string of either base64 or hex
    pub fn from_str(data: &str) -> Result<Self> {
        Self::from_base64(&data).or_else(|_| Self::from_hex(&data))
    }

    pub fn from_str_with_pow_check(data: &str, min_pow_score: u8) -> Result<Self> {
        Self::from_base64_with_pow_check(&data, min_pow_score)
            .or_else(|_| Self::from_hex_with_pow_check(&data, min_pow_score))
    }

    fn generate_signable_data(&self) -> Vec<u8> {
        let mut signable_data = serialize(&self.data).unwrap();
        signable_data.extend(serialize(&self.unix_time).unwrap());
        signable_data.extend(&self.public_key);
        signable_data.extend(serialize(&self.nonce).unwrap());

        signable_data
    }

    /// Get the Proof of Work Score
    pub fn get_pow_score(&self) -> u8 {
        let signable_data = self.generate_signable_data();
        calculate_pow_score(&signable_data)
    }

    /// Get the SHA256 hash of the serialized bytes of this object, as a string
    pub fn get_hash_hex(&self) -> String {
        hex::encode(Sha256::digest(&self.to_bytes()))
    }

    /// Get the SHA256 hash of the serialized bytes of this object, as an array of bytes
    pub fn get_hash(&self) -> [u8; 32] {
        let mut a = [0u8; 32];
        let h = Sha256::digest(&self.to_bytes());
        a.clone_from_slice(&h);
        a
    }

    fn new(
        data: SampiData,
        min_pow_score: Option<u8>,
        keypair: &SampiKeyPair,
        unix_time: Option<u64>,
        threads_count: u64,
    ) -> Result<Self> {
        let mut signable_data = serialize(&data)?;
        if signable_data.len() > MAX_DATA_LENGTH {
            return Err("Data too large".into());
        }

        #[cfg(not(target_arch = "wasm32"))]
        let unix_time = std::cmp::min(
            unix_time.unwrap_or(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64),
            2u64.pow(48) - 1,
        );

        #[cfg(target_arch = "wasm32")]
        let unix_time = std::cmp::min(unix_time.unwrap_or(Date::now() as u64), 2u64.pow(48) - 1);

        let mut s = Sampi {
            unix_time,
            public_key: keypair.keypair.public.to_bytes(),
            signature: [0; 64],
            nonce: 0,
            data,
        };

        signable_data.extend(serialize(&unix_time)?);
        signable_data.extend(keypair.keypair.public.as_bytes());

        let nonce = match min_pow_score {
            Some(min_pow_score) => {
                if threads_count == 1 {
                    find_nonce(min_pow_score, signable_data.clone())
                } else {
                    let (sender, receiver) = mpsc::channel();
                    let solution_found = Arc::new(AtomicBool::new(false));

                    for start in 0..threads_count {
                        let signable_data = signable_data.clone();
                        let sender = sender.clone();
                        let solution_found = solution_found.clone();
                        thread::spawn(move || {
                            find_nonce_threaded(
                                start,
                                threads_count,
                                min_pow_score,
                                signable_data,
                                &sender,
                                solution_found,
                            );
                        });
                    }
                    drop(sender);
                    receiver
                        .recv()
                        .map_err(|_| "Unable to find a POW solution".to_string())?
                }
            }
            None => 0,
        };

        signable_data.extend(serialize(&nonce)?);

        s.signature = keypair.keypair.sign(&signable_data).to_bytes();
        s.nonce = nonce;

        Ok(s)
    }
}

impl fmt::Debug for Sampi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sampi {{ data: {} }}", self.data)
    }
}

impl Eq for Sampi {}

impl Ord for Sampi {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.unix_time.cmp(&other.unix_time)
    }
}

impl PartialOrd for Sampi {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Sampi {
    fn eq(&self, other: &Self) -> bool {
        self.unix_time == other.unix_time
            && self.data == other.data
            && self.public_key == other.public_key
            && self.nonce == other.nonce
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SampiFilter {
    pub minimum_pow_score: u8,
    pub public_key: Option<[u8; 32]>,
    pub minimum_unix_time: Option<u64>,
    pub maximum_unix_time: Option<u64>,
    pub minimum_data_length: u16,
    pub maximum_data_length: u16,
    pub data_variant: Option<String>,
}

impl SampiFilter {
    /// Test whether a given Sampi Message matches this filter
    pub fn matches(&self, s: &Sampi) -> bool {
        if s.get_pow_score() < self.minimum_pow_score {
            return false;
        }

        if let Some(public_key) = self.public_key {
            if public_key != s.public_key {
                return false;
            }
        }

        if s.unix_time < self.minimum_unix_time.unwrap_or(0)
            || s.unix_time > self.maximum_unix_time.unwrap_or_else(|| 2u64.pow(48))
        {
            return false;
        }

        if let Some(data_variant) = &self.data_variant {
            if data_variant != &s.data.to_string() {
                return false;
            }
        }

        let data_length = serialize(&s.data).unwrap().len() as u16;
        data_length >= self.minimum_data_length && data_length <= self.maximum_data_length
    }
}

impl Default for SampiFilter {
    /// Create a new SampiFilter, which will match all Sampi messages
    fn default() -> SampiFilter {
        SampiFilter {
            minimum_pow_score: 0,
            public_key: None,
            minimum_unix_time: None,
            maximum_unix_time: None,
            minimum_data_length: 0,
            maximum_data_length: MAX_DATA_LENGTH as u16,
            data_variant: None,
        }
    }
}

fn calculate_pow_score(signable_data: &[u8]) -> u8 {
    let mut count = Sha512::digest(&signable_data)
        .iter()
        .map(|&i| i.count_ones())
        .sum();
    if count <= 256 {
        count = 256 - count;
    } else {
        count -= 256;
    }
    if count == 256 {
        count = 255;
    }
    count as u8
}

fn find_nonce(min_pow_score: u8, mut signable_data: Vec<u8>) -> u64 {
    signable_data.extend(vec![0; 4]);
    let signable_data_length = signable_data.len();

    for nonce in 0.. {
        signable_data.splice(signable_data_length - 4.., serialize(&nonce).unwrap());
        let pow_score = calculate_pow_score(&signable_data);

        if pow_score >= min_pow_score {
            return nonce;
        }
    }

    0
}

fn find_nonce_threaded(
    start: u64,
    offset: u64,
    min_pow_score: u8,
    mut signable_data: Vec<u8>,
    sender: &mpsc::Sender<u64>,
    solution_found: Arc<AtomicBool>,
) {
    signable_data.extend(vec![0; 4]);
    let signable_data_length = signable_data.len();
    for (i, nonce) in (start..u64::max_value())
        .step_by(offset as usize)
        .enumerate()
    {
        if i % 10000 == 0 && solution_found.load(Ordering::Relaxed) {
            return;
        }
        signable_data.splice(signable_data_length - 4.., serialize(&nonce).unwrap());

        let pow_score = calculate_pow_score(&signable_data);

        if pow_score >= min_pow_score {
            solution_found.store(true, Ordering::Relaxed);
            let _ = sender.send(nonce);
            return;
        }
    }
}

#[cfg(test)]
mod test;
