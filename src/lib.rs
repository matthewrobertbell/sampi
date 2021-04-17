#![allow(clippy::new_without_default)]
#![allow(clippy::upper_case_acronyms)]

use std::env;
use std::fmt;
use std::fs::{create_dir, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::str::FromStr;
use std::string::ToString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;

#[cfg(any(not(target_arch = "wasm32"), target_os = "wasi"))]
use std::time::{SystemTime, UNIX_EPOCH};

use base32::{decode as base32_decode, encode as base32_encode, Alphabet as Base32Alphabet};
use base64::decode_config as base64_decode_config;
use base64::encode_config as base64_encode_config;
use bincode::{serialize, Options};
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier};
use glob::glob;
use rand::Rng;
use rand_core::OsRng;
use rust_base58::{FromBase58, ToBase58};
use serde_big_array::big_array;
use serde_derive::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;

extern crate strum;
#[macro_use]
extern crate strum_macros;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use js_sys::Date;

big_array! { BigArray; }

pub const MAX_DATA_LENGTH: usize = 900;
const CROCKFORD_ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

#[derive(Error, Debug)]
pub enum SampiError {
    #[error("IO error")]
    IOError(#[from] std::io::Error),
    #[error("Validation error")]
    ValidationError,
    #[error("Data too large")]
    DataTooLargeError,
    #[error("IO Error")]
    BincodeError(#[from] bincode::Error),
    #[error("Decoding error")]
    DecodingError,
    #[error("Filesystem error")]
    FilesystemError,
    #[error("KeyPair error")]
    KeyPairError,
    #[error("SystemTime error")]
    SystemTimeError(#[from] std::time::SystemTimeError),
    #[error("POW error")]
    POWError,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug, Display)]
pub enum SampiData {
    // Primitive Types
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    I128(i128),
    F32(f32),
    F64(f64),
    Bool(bool),
    Char(char),
    Null,
    String(String),

    StringPair((String, String)),
    SampiDataPair((Box<SampiData>, Box<SampiData>)),

    // Sampi specific
    SampiFilter(SampiFilter),
    Sampi(Box<Sampi>),

    Array16Byte([u8; 16]),
    Array32Byte([u8; 32]),
    #[serde(with = "BigArray")]
    Array64Byte([u8; 64]),
    #[serde(with = "BigArray")]
    Array128Byte([u8; 128]),
    #[serde(with = "BigArray")]
    Array256Byte([u8; 256]),

    VecSampiData(Vec<SampiData>),
    Bytes(Vec<u8>),
}

impl From<u64> for SampiData {
    fn from(v: u64) -> Self {
        Self::U64(v)
    }
}

impl From<Vec<u8>> for SampiData {
    fn from(v: Vec<u8>) -> Self {
        Self::Bytes(v)
    }
}

impl From<[u8; 16]> for SampiData {
    fn from(v: [u8; 16]) -> Self {
        Self::Array16Byte(v)
    }
}

impl From<[u8; 32]> for SampiData {
    fn from(v: [u8; 32]) -> Self {
        Self::Array32Byte(v)
    }
}

impl From<[u8; 64]> for SampiData {
    fn from(v: [u8; 64]) -> Self {
        Self::Array64Byte(v)
    }
}

impl From<[u8; 128]> for SampiData {
    fn from(v: [u8; 128]) -> Self {
        Self::Array128Byte(v)
    }
}

impl From<[u8; 256]> for SampiData {
    fn from(v: [u8; 256]) -> Self {
        Self::Array256Byte(v)
    }
}

impl From<Vec<String>> for SampiData {
    fn from(v: Vec<String>) -> Self {
        Self::VecSampiData(v.into_iter().map(Self::String).collect())
    }
}

impl From<String> for SampiData {
    fn from(v: String) -> Self {
        Self::String(v)
    }
}

impl From<&str> for SampiData {
    fn from(v: &str) -> Self {
        Self::String(v.to_string())
    }
}

impl From<(String, String)> for SampiData {
    fn from(v: (String, String)) -> Self {
        Self::StringPair(v)
    }
}

impl From<(&str, &str)> for SampiData {
    fn from(v: (&str, &str)) -> Self {
        Self::StringPair((v.0.to_string(), v.1.to_string()))
    }
}

impl From<&[String]> for SampiData {
    fn from(v: &[String]) -> Self {
        Self::VecSampiData(v.iter().map(|s| Self::String(s.to_owned())).collect())
    }
}

impl From<Vec<(String, String)>> for SampiData {
    fn from(v: Vec<(String, String)>) -> Self {
        Self::VecSampiData(v.into_iter().map(Self::StringPair).collect())
    }
}

impl From<&[(String, String)]> for SampiData {
    fn from(v: &[(String, String)]) -> Self {
        Self::VecSampiData(
            v.iter()
                .map(|(s1, s2)| Self::StringPair((s1.to_owned(), s2.to_owned())))
                .collect(),
        )
    }
}

impl SampiData {
    pub fn human_readable(&self) -> String {
        match &self {
            SampiData::String(s) => s.to_string(),
            SampiData::Bytes(bytes) => format!("{:?}", bytes),
            SampiData::Null => "Null".to_string(),
            SampiData::VecSampiData(v) => format!("{:?}", v),
            SampiData::Array16Byte(v) => format!("{:?}", v),
            SampiData::Array32Byte(v) => format!("{:?}", v),
            SampiData::Array64Byte(v) => format!("{:?}", v),
            SampiData::Array128Byte(v) => format!("{:?}", v),
            SampiData::Array256Byte(v) => format!("{:?}", v),
            _ => "Unimplemented variant".to_string(),
        }
    }

    pub fn variant_name(&self) -> String {
        self.to_string()
    }

    pub fn variant(&self) -> u8 {
        match self {
            SampiData::U8 { .. } => 0,
            SampiData::U16 { .. } => 1,
            SampiData::U32 { .. } => 2,
            SampiData::U64 { .. } => 3,
            SampiData::U128 { .. } => 4,
            SampiData::I8 { .. } => 5,
            SampiData::I16 { .. } => 6,
            SampiData::I32 { .. } => 7,
            SampiData::I64 { .. } => 8,
            SampiData::I128 { .. } => 9,
            SampiData::F32 { .. } => 10,
            SampiData::F64 { .. } => 11,
            SampiData::Bool { .. } => 12,
            SampiData::Char { .. } => 13,
            SampiData::Null { .. } => 14,
            SampiData::String { .. } => 15,
            SampiData::StringPair { .. } => 16,
            SampiData::SampiFilter { .. } => 17,
            SampiData::Sampi { .. } => 18,
            SampiData::Array16Byte { .. } => 19,
            SampiData::Array32Byte { .. } => 20,
            SampiData::Array64Byte { .. } => 21,
            SampiData::Array128Byte { .. } => 22,
            SampiData::Array256Byte { .. } => 23,
            SampiData::VecSampiData { .. } => 24,
            SampiData::Bytes { .. } => 25,
            SampiData::SampiDataPair { .. } => 26,
        }
    }
}

pub struct SampiKeyPair {
    keypair: Keypair,
}

impl SampiKeyPair {
    pub fn new() -> Self {
        Self {
            keypair: Keypair::generate(&mut OsRng),
        }
    }
}

impl SampiKeyPair {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SampiError> {
        Ok(Self {
            keypair: Keypair::from_bytes(bytes).map_err(|_| SampiError::KeyPairError)?,
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

    fn data_dir() -> Result<PathBuf, SampiError> {
        let path = match env::var("SAMPI_KEYS_PATH") {
            Ok(env_path) => PathBuf::from(env_path),
            Err(_) => {
                let mut path = dirs::data_dir().ok_or(SampiError::FilesystemError)?;
                path.push("sampi");
                path
            }
        };

        if !&path.exists() {
            create_dir(&path)?;
        }
        Ok(path)
    }

    pub fn list_keys() -> Result<Vec<(String, SampiKeyPair)>, SampiError> {
        let mut path = Self::data_dir()?;
        path.push("*.key");

        let keys: Vec<_> = glob(path.to_str().ok_or(SampiError::FilesystemError)?)
            .map_err(|_| SampiError::FilesystemError)?
            .filter_map(|p| p.ok())
            .filter_map(|p| {
                p.file_stem()
                    .and_then(|p| p.to_os_string().into_string().ok())
            })
            .filter_map(|p| Self::load_from_file(&p).map(|kp| (p, kp)).ok())
            .collect();
        Ok(keys)
    }

    pub fn save_to_file(&self, name: &str) -> Result<(), SampiError> {
        let mut path = Self::data_dir()?;
        path.push(format!("{}.key", name));

        let mut writer = File::create(path)?;
        writer.write_all(&self.to_bytes())?;
        Ok(())
    }

    pub fn load_from_file(name: &str) -> Result<SampiKeyPair, SampiError> {
        let mut path = Self::data_dir()?;
        path.push(format!("{}.key", name));

        let mut f = File::open(path)?;
        let mut bytes = [0u8; 64];
        f.read_exact(&mut bytes)?;
        SampiKeyPair::from_bytes(&bytes)
    }

    pub fn new_sampi(&self) -> SampiBuilder {
        SampiBuilder::new(&self)
    }
}

#[derive(Clone)]
pub struct SampiBuilder<'a> {
    min_pow_score: Option<u8>,
    keypair: &'a SampiKeyPair,
    unix_time: Option<i64>,
    threads_count: u64,
}

impl<'a> SampiBuilder<'a> {
    fn new(keypair: &'a SampiKeyPair) -> Self {
        SampiBuilder {
            min_pow_score: None,
            keypair,
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

    pub fn with_unix_time(mut self, unix_time: i64) -> Self {
        self.unix_time = Some(unix_time);
        self
    }

    pub fn with_random_unix_time(mut self) -> Self {
        self.unix_time = Some(OsRng.gen_range(std::i64::MIN, std::i64::MAX));
        self
    }

    pub fn build(&self, data: Vec<SampiData>) -> Result<Sampi, SampiError> {
        Sampi::new(
            data,
            self.min_pow_score,
            &self.keypair,
            self.unix_time,
            self.threads_count,
        )
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub enum Sampi {
    SimpleV1 {
        public_key: [u8; 32],
        unix_time: i64,
        data: Vec<SampiData>,
        #[serde(with = "BigArray")]
        signature: [u8; 64],
    },
    ProofOfWorkV1 {
        public_key: [u8; 32],
        unix_time: i64,
        data: Vec<SampiData>,
        #[serde(with = "BigArray")]
        signature: [u8; 64],
        nonce: u64,
    },
}

impl FromStr for Sampi {
    type Err = SampiError;

    /// Attempt to deserialize from a string of base64, base58, base32, or hex
    fn from_str(data: &str) -> std::result::Result<Self, Self::Err> {
        Self::from_base64(&data)
            .or_else(|_| Self::from_base58(&data))
            .or_else(|_| Self::from_base32(&data))
            .or_else(|_| Self::from_hex(&data))
    }
}

impl Sampi {
    pub fn public_key(&self) -> [u8; 32] {
        match self {
            Sampi::SimpleV1 { public_key, .. } => *public_key,
            Sampi::ProofOfWorkV1 { public_key, .. } => *public_key,
        }
    }

    fn signature(&self) -> [u8; 64] {
        match self {
            Sampi::SimpleV1 { signature, .. } => *signature,
            Sampi::ProofOfWorkV1 { signature, .. } => *signature,
        }
    }

    fn nonce(&self) -> Option<u64> {
        match self {
            Sampi::SimpleV1 { .. } => None,
            Sampi::ProofOfWorkV1 { nonce, .. } => Some(*nonce),
        }
    }

    pub fn unix_time(&self) -> i64 {
        match self {
            Sampi::SimpleV1 { unix_time, .. } => *unix_time,
            Sampi::ProofOfWorkV1 { unix_time, .. } => *unix_time,
        }
    }

    pub fn data(&self) -> &Vec<SampiData> {
        match self {
            Sampi::SimpleV1 { data, .. } => data,
            Sampi::ProofOfWorkV1 { data, .. } => data,
        }
    }

    /// Attempt to deserialize a Sampi object from a slice of bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SampiError> {
        let s: Sampi = bincode::options()
            .with_limit(1024)
            .allow_trailing_bytes()
            .deserialize(&bytes)?;

        let signable_data = s.generate_signable_data();

        let public_key =
            PublicKey::from_bytes(&s.public_key()).map_err(|_| SampiError::ValidationError)?;
        let signature = Signature::from(s.signature());
        public_key
            .verify(&signable_data, &signature)
            .map_err(|_| SampiError::ValidationError)?;
        Ok(s)
    }

    /// Attempt to deserialize multiple Sampi objects from a slice of bytes
    pub fn from_bytes_iterator(bytes: &[u8]) -> impl Iterator<Item = Self> + '_ {
        let mut bytes_offset = 0;
        std::iter::from_fn(move || {
            Self::from_bytes(&bytes[bytes_offset..]).ok().map(|s| {
                bytes_offset += s.to_bytes().len() as usize;
                s
            })
        })
    }

    /// Serialize to a Vector of bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::options()
            .with_limit(1024)
            .serialize(&self)
            .unwrap()
    }

    /// Attempt to deserialize a Sampi object from a &str of hex
    pub fn from_hex(hex_string: &str) -> Result<Self, SampiError> {
        let decoded = hex::decode(hex_string).map_err(|_| SampiError::DecodingError)?;
        Self::from_bytes(&decoded)
    }

    /// Serialize to a hex string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.to_bytes())
    }

    /// Attempt to deserialize a Sampi object from a &str of base32
    pub fn from_base32(base32_string: &str) -> Result<Self, SampiError> {
        if !base32_string
            .bytes()
            .all(|b| CROCKFORD_ALPHABET.contains(&b.to_ascii_uppercase()))
        {
            return Err(SampiError::DecodingError);
        }
        let decoded = base32_decode(Base32Alphabet::Crockford, base32_string)
            .ok_or(SampiError::DecodingError)?;
        Self::from_bytes(&decoded)
    }

    /// Serialize to a base32 string
    pub fn to_base32(&self) -> String {
        base32_encode(Base32Alphabet::Crockford, &self.to_bytes())
    }

    /// Attempt to deserialize a Sampi object from a &str of base58
    pub fn from_base58(base58_string: &str) -> Result<Self, SampiError> {
        let decoded = base58_string
            .from_base58()
            .map_err(|_| SampiError::DecodingError)?;
        Self::from_bytes(&decoded)
    }

    /// Serialize to a base58 string
    pub fn to_base58(&self) -> String {
        self.to_bytes().to_base58()
    }

    /// Serialize to a base64 string
    pub fn to_base64(&self) -> String {
        base64_encode_config(&self.to_bytes(), base64::URL_SAFE_NO_PAD)
    }

    /// Attempt to deserialize a Sampi object from a &str of base64
    pub fn from_base64(base64_string: &str) -> Result<Self, SampiError> {
        let decoded = base64_decode_config(base64_string, base64::URL_SAFE)
            .map_err(|_| SampiError::DecodingError)?;
        Self::from_bytes(&decoded)
    }

    fn generate_signable_data(&self) -> Vec<u8> {
        let mut signable_data = bincode::options()
            .with_limit(1024)
            .serialize(&self.data())
            .unwrap();
        signable_data.extend(serialize(&self.unix_time()).unwrap());
        signable_data.extend(&self.public_key());
        if let Some(nonce) = self.nonce() {
            signable_data.extend(serialize(&nonce).unwrap());
        }

        signable_data
    }

    /// Get the Proof of Work Score
    pub fn get_pow_score(&self) -> Option<u8> {
        match self {
            Sampi::SimpleV1 { .. } => None,
            Sampi::ProofOfWorkV1 { .. } => {
                Some(calculate_pow_score(&self.generate_signable_data()))
            }
        }
    }

    /// Public key as a hex string
    pub fn get_public_key_as_hex(&self) -> String {
        hex::encode(&self.public_key())
    }

    /// Get the SHA256 hash of the serialized bytes of this object, as a string
    pub fn get_hash_as_hex(&self) -> String {
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
        data: Vec<SampiData>,
        min_pow_score: Option<u8>,
        keypair: &SampiKeyPair,
        unix_time: Option<i64>,
        threads_count: u64,
    ) -> Result<Self, SampiError> {
        let mut signable_data = bincode::options().with_limit(1024).serialize(&data)?;
        if signable_data.len() > MAX_DATA_LENGTH + 5 {
            return Err(SampiError::DataTooLargeError);
        }

        #[cfg(any(not(target_arch = "wasm32"), target_os = "wasi"))]
        let unix_time =
            unix_time.unwrap_or(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64);

        #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
        let unix_time = unix_time.unwrap_or(Date::now() as i64);

        signable_data.extend(serialize(&unix_time)?);
        signable_data.extend(keypair.keypair.public.as_bytes());

        let s = if let Some(min_pow_score) = min_pow_score {
            let nonce = if min_pow_score == 0 {
                0
            } else if threads_count == 1 {
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
                receiver.recv().map_err(|_| SampiError::POWError)?
            };

            signable_data.extend(serialize(&nonce)?);

            Sampi::ProofOfWorkV1 {
                unix_time,
                public_key: keypair.keypair.public.to_bytes(),
                signature: keypair.keypair.sign(&signable_data).to_bytes(),
                nonce,
                data,
            }
        } else {
            Sampi::SimpleV1 {
                unix_time,
                public_key: keypair.keypair.public.to_bytes(),
                signature: keypair.keypair.sign(&signable_data).to_bytes(),
                data,
            }
        };

        Ok(s)
    }
}

impl fmt::Debug for Sampi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sampi {{ data: {:?} }}", self.data())
    }
}

impl Eq for Sampi {}

impl Ord for Sampi {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.unix_time().cmp(&other.unix_time())
    }
}

impl PartialOrd for Sampi {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Sampi {
    fn eq(&self, other: &Self) -> bool {
        self.unix_time() == other.unix_time()
            && self.data() == other.data()
            && self.public_key() == other.public_key()
            && self.nonce() == other.nonce()
    }
}

/// The current unix time, in milliseconds
pub fn get_unix_time_millis() -> Option<i64> {
    #[cfg(any(not(target_arch = "wasm32"), target_os = "wasi"))]
    return Some(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_millis() as i64,
    );

    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    Some(Date::now() as i64)
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Copy)]
pub struct SampiFilter {
    pub minimum_pow_score: u8,
    pub public_key: Option<[u8; 32]>,
    pub minimum_unix_time: Option<i64>,
    pub maximum_unix_time: Option<i64>,
    pub maximum_unix_time_age: Option<i64>,
    pub minimum_data_length: u16,
    pub maximum_data_length: u16,
    pub data_variant: Option<u8>,
}

impl SampiFilter {
    /// Test whether a given Sampi Message matches this filter
    pub fn matches(&self, s: &Sampi, current_unix_time: Option<i64>) -> bool {
        if self.minimum_pow_score != 0
            && s.get_pow_score()
                .map(|score| score < self.minimum_pow_score)
                .unwrap_or(false)
        {
            return false;
        }

        if matches!(self.public_key, Some(public_key) if public_key != s.public_key()) {
            return false;
        }

        if s.unix_time() < self.minimum_unix_time.unwrap_or(0)
            || s.unix_time() > self.maximum_unix_time.unwrap_or_else(i64::max_value)
        {
            return false;
        }

        if let Some(maximum_unix_time_age) = self.maximum_unix_time_age {
            if let Some(current_unix_time) = current_unix_time {
                if current_unix_time - s.unix_time() > maximum_unix_time_age {
                    return false;
                }
            } else {
                return false;
            }
        }

        if self.data_variant.is_some()
            && !s
                .data()
                .iter()
                .any(|d| Some(d.variant()) == self.data_variant)
        {
            return false;
        }

        let data_length = serialize(&s.data()).unwrap().len() as u16;
        data_length >= self.minimum_data_length && data_length <= self.maximum_data_length
    }
    /// Create a new SampiFilter, which will match all Sampi messages
    pub fn new() -> SampiFilter {
        SampiFilter {
            minimum_pow_score: 0,
            public_key: None,
            minimum_unix_time: None,
            maximum_unix_time: None,
            maximum_unix_time_age: None,
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
