use std::env;
use std::error::Error;
use std::fs::{create_dir, File};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;

#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};

use base64::decode_config as base64_decode_config;
use base64::encode_config as base64_encode_config;
use bincode::{deserialize, serialize};
use byteorder::{ByteOrder, LittleEndian};
use dirs;
use ed25519_dalek::{Keypair, PublicKey, Signature};
use glob::glob;
use hex;
use rand::rngs::OsRng;
use rand::Rng;
use serde_big_array::big_array;
use serde_derive::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::io::{Read, Write};
use std::path::PathBuf;

#[cfg(target_arch = "wasm32")]
use js_sys::Date;

big_array! { BigArray; }

pub const MAX_DATA_LENGTH: usize = 900;
const SAMPI_OVERHEAD: usize = 124;

pub type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync + 'static>>;

pub struct SampiKeyPair {
    keypair: Keypair,
}

impl SampiKeyPair {
    pub fn new() -> Result<Self> {
        let mut csprng: OsRng = OsRng::new().unwrap();
        Ok(Self {
            keypair: Keypair::generate(&mut csprng),
        })
    }

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
        let env_path = env::vars()
            .filter(|(k, _)| k == "SAMPI_KEYS_PATH")
            .map(|(_, v)| PathBuf::from(v))
            .next();
        let path = match env_path {
            Some(env_path) => env_path,
            None => {
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
        writer.write(&bytes)?;
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
    metadata: [u8; 16],
    min_pow_score: Option<u8>,
    ss_keypair: &'a SampiKeyPair,
    unix_time: Option<u64>,
    threads_count: u32,
}

impl<'a> SampiBuilder<'a> {
    fn new(ss_keypair: &'a SampiKeyPair) -> Self {
        SampiBuilder {
            metadata: [0; 16],
            min_pow_score: None,
            ss_keypair,
            unix_time: None,
            threads_count: 1,
        }
    }

    pub fn with_metadata(mut self, metadata: [u8; 16]) -> Self {
        self.metadata = metadata;
        self
    }

    pub fn with_random_metadata(mut self) -> Self {
        OsRng::new().unwrap().fill(&mut self.metadata);
        self
    }

    pub fn with_pow(mut self, min_pow_score: u8) -> Self {
        self.min_pow_score = Some(min_pow_score);
        self.threads_count = num_cpus::get() as u32;
        self
    }

    pub fn with_pow_threads(mut self, threads_count: u32) -> Self {
        self.threads_count = threads_count;
        self
    }

    pub fn with_unix_time(mut self, unix_time: u64) -> Self {
        self.unix_time = Some(unix_time);
        self
    }

    pub fn with_random_unix_time(mut self) -> Self {
        self.unix_time = Some(OsRng::new().unwrap().gen_range(0, 2u64.pow(48) - 1));
        self
    }

    pub fn build(&self, data: impl Into<Vec<u8>>) -> Result<Sampi> {
        Sampi::new(
            data.into(),
            self.metadata,
            self.min_pow_score,
            &self.ss_keypair,
            self.unix_time,
            self.threads_count,
        )
    }

    pub fn build_from_reader<R: 'a + Read>(&'a self, mut r: R) -> impl Iterator<Item = Sampi> + 'a {
        let mut count: u32 = 0;
        let mut buf = [0; MAX_DATA_LENGTH];
        let mut previous_hash = [0; 4];
        let mut metadata = [0; 16];

        let mut random_id = [0u8; 8];
        OsRng::new().unwrap().fill(&mut random_id);

        std::iter::from_fn(move || match r.read(&mut buf) {
            Ok(0) => None,
            Ok(n) => {
                count += 1;
                dbg!(count);
                dbg!(n);

                metadata.copy_from_slice(
                    serialize(&(random_id, count, previous_hash))
                        .unwrap()
                        .as_slice(),
                );

                let s = self
                    .ss_keypair
                    .new_sampi()
                    .with_metadata(metadata)
                    .build(&buf[0..n])
                    .unwrap();

                previous_hash.copy_from_slice(&s.get_hash_bytes()[..4]);

                Some(s)
            }
            Err(_) => None,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub struct Sampi {
    length: u16,
    pub data: Vec<u8>,
    unix_time: [u8; 6],
    pub metadata: [u8; 16],
    public_key: [u8; 32],
    #[serde(with = "BigArray")]
    signature: [u8; 64],
    nonce: u32,
}

impl Sampi {
    pub fn data_as_string(&self) -> Result<String> {
        std::str::from_utf8(&self.data)
            .map(|s| s.to_string().to_owned())
            .map_err(|_| "Not a valid UTF8 string".into())
    }

    pub fn data_as_hex(&self) -> String {
        hex::encode(&self.data)
    }

    pub fn public_key_as_hex(&self) -> String {
        hex::encode(&self.public_key)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < SAMPI_OVERHEAD {
            return Err("Deserialization input data is too small".into());
        }
        if bytes.len() > SAMPI_OVERHEAD + MAX_DATA_LENGTH {
            return Err("Deserialization input data is too large".into());
        }
        let bytes = bytes.to_vec();
        let length: u16 = deserialize(&bytes[..2])?;
        let real_length = length & 0b0000_0011_1111_1111;

        if real_length as usize > bytes.len() - SAMPI_OVERHEAD {
            return Err("Deserialization input data is too small".into());
        }

        let serialized_real_length = serialize(&real_length).unwrap();
        let mut length_array = [0; 8];
        length_array[0] = serialized_real_length[0];
        length_array[1] = serialized_real_length[1];

        let mut new_bytes = Vec::with_capacity(bytes.len() + 8);
        new_bytes.extend_from_slice(&bytes[..2]);
        new_bytes.extend(&length_array);
        new_bytes.extend_from_slice(&bytes[2..real_length as usize + SAMPI_OVERHEAD]);

        Ok(deserialize(&new_bytes)?)
    }

    fn serialize(&self) -> Vec<u8> {
        let bytes = serialize(&self).unwrap().to_vec();

        let mut new_bytes = Vec::with_capacity(bytes.len() - 8);
        new_bytes.extend_from_slice(&bytes[..2]);
        new_bytes.extend_from_slice(&bytes[10..]);

        new_bytes
    }

    fn validate(self, serialized_data: &[u8], min_pow_score: Option<u8>) -> Result<Self> {
        let real_length = self.length & 0b0000_0011_1111_1111;
        if self.data.len() > MAX_DATA_LENGTH {
            return Err("Data too large".into());
        }

        let serialized_data = &serialized_data[..real_length as usize + SAMPI_OVERHEAD];

        if real_length as usize + SAMPI_OVERHEAD != serialized_data.len() {
            return Err("Length field doesn't match the serialized data length".into());
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
        base64_encode_config(&self.serialize(), base64::URL_SAFE).to_owned()
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
        hex::encode(&self.serialize()).to_owned()
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

    /// Get the metadata as a hex string
    pub fn metadata_as_hex(&self) -> String {
        hex::encode(&self.metadata).to_owned()
    }

    fn generate_signable_data(&self) -> Vec<u8> {
        let mut signable_data = self.data.to_owned().to_vec();

        let original_length = self.length & 0b0000_0011_1111_1111;
        signable_data.extend(serialize(&original_length).unwrap());
        signable_data.extend(&self.unix_time);
        signable_data.extend(&self.metadata);
        signable_data.extend(&self.public_key);
        signable_data.extend(serialize(&self.nonce).unwrap());

        signable_data
    }

    /// Get the Proof of Work Score
    pub fn get_pow_score(&self) -> u8 {
        let signable_data = self.generate_signable_data();
        calculate_pow_score(&signable_data)
    }

    /// Get the unix time value
    pub fn get_unix_time(&self) -> u64 {
        LittleEndian::read_u48(&self.unix_time)
    }

    /// Get the SHA256 hash of the serialized bytes of this object, as a string
    pub fn get_hash(&self) -> String {
        hex::encode(Sha256::digest(&self.to_bytes()))
    }

    /// Get the SHA256 hash of the serialized bytes of this object, as a Vector of bytes
    pub fn get_hash_bytes(&self) -> Vec<u8> {
        Sha256::digest(&self.to_bytes()).to_vec()
    }

    fn new(
        data: Vec<u8>,
        metadata: [u8; 16],
        min_pow_score: Option<u8>,
        keypair: &SampiKeyPair,
        unix_time: Option<u64>,
        threads_count: u32,
    ) -> Result<Self> {
        if data.len() > MAX_DATA_LENGTH {
            return Err("Data too large".into());
        }

        #[cfg(not(target_arch = "wasm32"))]
        let unix_time = std::cmp::min(
            unix_time.unwrap_or(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64),
            2u64.pow(48) - 1,
        );

        #[cfg(target_arch = "wasm32")]
        let unix_time = std::cmp::min(unix_time.unwrap_or(Date::now() as u64), 2u64.pow(48) - 1);

        let mut unix_time_array = [0; 6];
        LittleEndian::write_u48(&mut unix_time_array, unix_time);

        let mut signable_data = data.clone();

        let original_length = data.len() as u16;
        let mut length_mutation = LittleEndian::read_u16(&Sha512::digest(&data)[..2]);
        length_mutation &= 0b1111_1100_0000_0000;
        let length = length_mutation + data.len() as u16;

        let mut s = Sampi {
            length,
            unix_time: unix_time_array,
            metadata,
            public_key: keypair.keypair.public.to_bytes(),
            signature: [0; 64],
            nonce: 0,
            data,
        };

        signable_data.extend(serialize(&original_length)?);
        signable_data.extend(&unix_time_array);
        signable_data.extend(&metadata);
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

impl Eq for Sampi {}

impl Ord for Sampi {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.get_unix_time().cmp(&other.get_unix_time())
    }
}

impl PartialOrd for Sampi {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Sampi {
    fn eq(&self, other: &Self) -> bool {
        self.get_unix_time() == other.get_unix_time()
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SampiFilter {
    pub minimum_pow_score: u8,
    pub public_key: Option<[u8; 32]>,
    pub minimum_unix_time: Option<u64>,
    pub maximum_unix_time: Option<u64>,
    pub minimum_data_length: u16,
    pub maximum_data_length: u16,
    pub metadata: [Option<u8>; 16],
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

        let unix_time = s.get_unix_time();
        if unix_time < self.minimum_unix_time.unwrap_or(0)
            || unix_time > self.maximum_unix_time.unwrap_or(2u64.pow(48))
        {
            return false;
        }

        let data_length = s.data.len() as u16;
        if data_length < self.minimum_data_length || data_length > self.maximum_data_length {
            return false;
        }

        self.metadata
            .iter()
            .zip(s.metadata.iter())
            .all(|(filter_byte, metadata_byte)| {
                filter_byte.map(|f_b| f_b == *metadata_byte).unwrap_or(true)
            })
    }

    /// Create a new SampiFilter, which will match all Sampi messages
    pub fn new() -> SampiFilter {
        SampiFilter {
            minimum_pow_score: 0,
            public_key: None,
            minimum_unix_time: None,
            maximum_unix_time: None,
            minimum_data_length: 0,
            maximum_data_length: MAX_DATA_LENGTH as u16,
            metadata: [None; 16],
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
        count = count - 256;
    }
    if count == 256 {
        count = 255;
    }
    count as u8
}

fn find_nonce(min_pow_score: u8, signable_data: Vec<u8>) -> u32 {
    let mut signable_data = signable_data.to_owned();
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
    start: u32,
    offset: u32,
    min_pow_score: u8,
    signable_data: Vec<u8>,
    sender: &mpsc::Sender<u32>,
    solution_found: Arc<AtomicBool>,
) {
    let mut signable_data = signable_data.to_owned();
    signable_data.extend(vec![0; 4]);
    let signable_data_length = signable_data.len();
    for (i, nonce) in (start..u32::max_value())
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
