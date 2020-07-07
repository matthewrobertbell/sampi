#![allow(clippy::new_without_default)]

use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::fmt;
use std::fs::{create_dir, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
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
use ed25519_dalek::{Keypair, PublicKey, Signature};
use glob::glob;
use rand::Rng;
use rand_core::OsRng;
use raptorq::{Decoder, Encoder, EncodingPacket, ObjectTransmissionInformation};
use rust_base58::{FromBase58, ToBase58};
use serde_big_array::big_array;
use serde_derive::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

extern crate strum;
#[macro_use]
extern crate strum_macros;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use js_sys::Date;

big_array! { BigArray; }

pub const MAX_DATA_LENGTH: usize = 900;
const RAPTOR_SERIALIZED_PACKET_SIZE: usize = 860;
const CROCKFORD_ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync + 'static>>;

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

    // Vecs of primitive types
    VecU8(Vec<u8>),
    VecU16(Vec<u16>),
    VecU32(Vec<u32>),
    VecU64(Vec<u64>),
    VecU128(Vec<u128>),
    VecI8(Vec<i8>),
    VecI16(Vec<i16>),
    VecI32(Vec<i32>),
    VecI64(Vec<i64>),
    VecI128(Vec<i128>),
    VecF32(Vec<f32>),
    VecF64(Vec<f64>),
    VecBool(Vec<bool>),
    VecChar(Vec<char>),
    VecString(Vec<String>),

    // Vecs of Tuples
    VecTupleStringString(Vec<(String, String)>),
    VecTupleU8U8(Vec<(u8, u8)>),
    VecTupleU16U16(Vec<(u16, u16)>),
    VecTupleU32U32(Vec<(u32, u32)>),
    VecTupleU64U64(Vec<(u64, u64)>),
    VecTupleStringU8(Vec<(String, u8)>),
    VecTupleStringU16(Vec<(String, u16)>),
    VecTupleStringU32(Vec<(String, u32)>),
    VecTupleStringU64(Vec<(String, u64)>),

    // Vecs of arrays of bytes
    VecArray16Byte(Vec<[u8; 16]>),
    VecArray32Byte(Vec<[u8; 32]>),

    // Sampi specific
    SampiFilter(SampiFilter),
    Sampi(Box<Sampi>),
    VecSampi(Vec<Sampi>),
    VecSampiFilter(Vec<SampiFilter>),
    SampiRaptorPacket {
        data: Vec<u8>,
        stream_id: u64,
        block_count: u32,
        total_bytes: Option<core::num::NonZeroU64>,
        object_transmission_information: ObjectTransmissionInformation,
    },

    // Useful tuples
    OptionalArray32ByteAndString((Option<[u8; 32]>, String)),
    OptionalArray32ByteAndVecU8((Option<[u8; 32]>, Vec<u8>)),
    OptionalArray32ByteAndVecString((Option<[u8; 32]>, Vec<String>)),
}

impl SampiData {
    pub fn human_readable(&self) -> String {
        match &self {
            SampiData::String(s) => s.to_string(),
            SampiData::U8(bytes) => format!("{:?}", bytes),
            SampiData::Null => "Null".to_string(),
            SampiData::OptionalArray32ByteAndString((array, string)) => {
                format!("{:?} - {:?}", array, string)
            }
            SampiData::OptionalArray32ByteAndVecU8((array, bytes)) => {
                format!("{:?} - {:?}", array, bytes)
            }
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
            SampiData::VecU8 { .. } => 16,
            SampiData::VecU16 { .. } => 17,
            SampiData::VecU32 { .. } => 18,
            SampiData::VecU64 { .. } => 19,
            SampiData::VecU128 { .. } => 20,
            SampiData::VecI8 { .. } => 21,
            SampiData::VecI16 { .. } => 22,
            SampiData::VecI32 { .. } => 23,
            SampiData::VecI64 { .. } => 24,
            SampiData::VecI128 { .. } => 25,
            SampiData::VecF32 { .. } => 26,
            SampiData::VecF64 { .. } => 27,
            SampiData::VecBool { .. } => 28,
            SampiData::VecChar { .. } => 29,
            SampiData::VecString { .. } => 30,
            SampiData::VecTupleStringString { .. } => 31,
            SampiData::VecTupleU8U8 { .. } => 32,
            SampiData::VecTupleU16U16 { .. } => 33,
            SampiData::VecTupleU32U32 { .. } => 34,
            SampiData::VecTupleU64U64 { .. } => 35,
            SampiData::VecTupleStringU8 { .. } => 36,
            SampiData::VecTupleStringU16 { .. } => 37,
            SampiData::VecTupleStringU32 { .. } => 38,
            SampiData::VecTupleStringU64 { .. } => 39,
            SampiData::VecArray16Byte { .. } => 40,
            SampiData::VecArray32Byte { .. } => 41,
            SampiData::SampiFilter { .. } => 42,
            SampiData::Sampi { .. } => 43,
            SampiData::VecSampi { .. } => 44,
            SampiData::VecSampiFilter { .. } => 45,
            SampiData::SampiRaptorPacket { .. } => 46,
            SampiData::OptionalArray32ByteAndString { .. } => 47,
            SampiData::OptionalArray32ByteAndVecU8 { .. } => 48,
            SampiData::OptionalArray32ByteAndVecString { .. } => 49,
        }
    }
}

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Debug, Display)]
pub enum SampiMetadata {
    None,
    Bytes([u8; 12]),
    Counter(u64),
    CounterAndBytes((u32, [u8; 8])),
    CounterPair((u32, u32)),
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

    pub fn save_to_file<T: AsRef<Path>>(&self, name: T) -> Result<()> {
        let mut path = Self::data_dir()?;
        path.push(name);
        path.push(".key");

        let mut writer = File::create(path)?;
        writer.write_all(&self.to_bytes())?;
        Ok(())
    }

    pub fn load_from_file<T: AsRef<Path>>(name: T) -> Result<SampiKeyPair> {
        let mut path = Self::data_dir()?;
        path.push(name);
        path.push(".key");

        let mut f = File::open(path)?;
        let mut bytes = vec![0u8; 64];
        f.read_exact(&mut bytes)?;
        Ok(SampiKeyPair::from_bytes(&bytes)?)
    }

    pub fn new_sampi(&self) -> SampiBuilder {
        SampiBuilder::new(&self)
    }
}

struct SampiRaptorStream {
    sampis: HashMap<u32, Vec<Sampi>>,
    current_block_count: u32,
    total_bytes: Option<core::num::NonZeroU64>,
    pub stream_id: Option<u64>,
    public_key: Option<[u8; 32]>,
}

impl SampiRaptorStream {
    fn new() -> SampiRaptorStream {
        SampiRaptorStream {
            sampis: HashMap::new(),
            current_block_count: 0,
            total_bytes: None,
            stream_id: None,
            public_key: None,
        }
    }

    fn insert(&mut self, s: Sampi) {
        if self.public_key.is_none() {
            self.public_key = Some(s.public_key);
        }
        if Some(s.public_key) != self.public_key {
            return;
        }
        if let SampiData::SampiRaptorPacket {
            stream_id,
            block_count,
            total_bytes,
            ..
        } = &s.data
        {
            if self.total_bytes.is_none() {
                self.total_bytes = *total_bytes;
            }
            if self.stream_id.is_none() {
                self.stream_id = Some(*stream_id);
            }
            if *block_count >= self.current_block_count && Some(*stream_id) == self.stream_id {
                let vec_entry = self.sampis.entry(*block_count).or_insert_with(Vec::new);

                if !vec_entry.contains(&s) {
                    vec_entry.push(s);
                }
            }
        }
    }
}

impl Iterator for SampiRaptorStream {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Vec<u8>> {
        if let Some(sampis) = self.sampis.get(&self.current_block_count) {
            let object_transmission_information = match sampis.first()?.data.clone() {
                SampiData::SampiRaptorPacket {
                    object_transmission_information,
                    ..
                } => Some(object_transmission_information),
                _ => None,
            }?;
            if sampis.len()
                >= object_transmission_information.transfer_length() as usize
                    / RAPTOR_SERIALIZED_PACKET_SIZE
            {
                let mut decoder = Decoder::new(object_transmission_information);
                for s in sampis {
                    if let SampiData::SampiRaptorPacket { data, .. } = &s.data {
                        if let Some(decoded) = decoder.decode(EncodingPacket::deserialize(data)) {
                            self.current_block_count += 1;
                            self.sampis.remove(&self.current_block_count);
                            return Some(decoded);
                        }
                    }
                }
            }
        }
        None
    }
}

#[derive(Clone)]
pub struct SampiBuilder<'a> {
    min_pow_score: Option<u8>,
    ss_keypair: &'a SampiKeyPair,
    unix_time: Option<i64>,
    threads_count: u64,
    metadata: SampiMetadata,
}

impl<'a> SampiBuilder<'a> {
    fn new(ss_keypair: &'a SampiKeyPair) -> Self {
        SampiBuilder {
            min_pow_score: None,
            ss_keypair,
            unix_time: None,
            threads_count: 1,
            metadata: SampiMetadata::None,
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

    pub fn with_metadata(mut self, metadata: SampiMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    pub fn with_unix_time(mut self, unix_time: i64) -> Self {
        self.unix_time = Some(unix_time);
        self
    }

    pub fn with_random_unix_time(mut self) -> Self {
        self.unix_time = Some(OsRng.gen_range(0, std::i64::MAX));
        self
    }

    pub fn build(&self, data: SampiData) -> Result<Sampi> {
        Sampi::new(
            data,
            self.metadata,
            self.min_pow_score,
            &self.ss_keypair,
            self.unix_time,
            self.threads_count,
        )
    }

    pub fn build_raptor_stream(
        &'a self,
        mut r: impl Read + 'a,
        stream_id: u64,
        total_bytes: Option<core::num::NonZeroU64>,
    ) -> impl Iterator<Item = Vec<Sampi>> + 'a {
        let mut block_count: u32 = 0;
        let mut buf = [0; 64 * 1024];

        std::iter::from_fn(move || match r.read(&mut buf) {
            Ok(0) => None,
            Ok(n) => {
                block_count += 1;

                let repair_packets_count = std::cmp::max(n / RAPTOR_SERIALIZED_PACKET_SIZE, 15);

                let encoder =
                    Encoder::with_defaults(&buf[0..n], RAPTOR_SERIALIZED_PACKET_SIZE as u16);
                Some(
                    encoder
                        .get_encoded_packets(repair_packets_count as u32)
                        .into_iter()
                        .map(|packet| {
                            self.build(SampiData::SampiRaptorPacket {
                                stream_id,
                                block_count: block_count - 1,
                                total_bytes,
                                data: packet.serialize(),
                                object_transmission_information: encoder.get_config(),
                            })
                            .unwrap()
                        })
                        .collect(),
                )
            }
            Err(_) => None,
        })
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Sampi {
    pub public_key: [u8; 32],
    pub unix_time: i64,
    pub data: SampiData,
    pub metadata: SampiMetadata,
    #[serde(with = "BigArray")]
    signature: [u8; 64],
    nonce: u64,
}

impl FromStr for Sampi {
    type Err = Box<dyn Error + Send + Sync + 'static>;

    /// Attempt to deserialize from a string of base64, base58, base32, or hex
    fn from_str(data: &str) -> std::result::Result<Self, Self::Err> {
        Self::from_base64(&data)
            .or_else(|_| Self::from_base58(&data))
            .or_else(|_| Self::from_base32(&data))
            .or_else(|_| Self::from_hex(&data))
    }
}

impl Sampi {
    /// Attempt to deserialize a Sampi object from a slice of bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let s: Sampi = bincode::options()
            .with_limit(1024)
            .allow_trailing_bytes()
            .deserialize(&bytes)?;

        let signable_data = s.generate_signable_data();

        let public_key =
            PublicKey::from_bytes(&s.public_key).map_err(|_| "Validation Error".to_string())?;
        let signature =
            Signature::from_bytes(&s.signature).map_err(|_| "Validation Error".to_string())?;
        public_key
            .verify(&signable_data, &signature)
            .map_err(|_| "Validation Error".to_string())?;
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
    pub fn from_hex(hex_string: &str) -> Result<Self> {
        let decoded = hex::decode(hex_string)?;
        Self::from_bytes(&decoded)
    }

    /// Serialize to a hex string
    pub fn to_hex(&self) -> String {
        hex::encode(&self.to_bytes())
    }

    /// Attempt to deserialize a Sampi object from a &str of base32
    pub fn from_base32(base32_string: &str) -> Result<Self> {
        if !base32_string
            .bytes()
            .all(|b| CROCKFORD_ALPHABET.contains(&b.to_ascii_uppercase()))
        {
            return Err("Not a valid Base32 string".into());
        }
        let decoded = base32_decode(Base32Alphabet::Crockford, base32_string)
            .ok_or_else(|| "Base32 Decoding Error".to_string())?;
        Self::from_bytes(&decoded)
    }

    /// Serialize to a base32 string
    pub fn to_base32(&self) -> String {
        base32_encode(Base32Alphabet::Crockford, &self.to_bytes())
    }

    /// Attempt to deserialize a Sampi object from a &str of base58
    pub fn from_base58(base58_string: &str) -> Result<Self> {
        let decoded = base58_string
            .from_base58()
            .map_err(|_| "Base58 Decoding Error".to_string())?;
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
    pub fn from_base64(base64_string: &str) -> Result<Self> {
        let decoded = base64_decode_config(base64_string, base64::URL_SAFE)?;
        Self::from_bytes(&decoded)
    }

    fn generate_signable_data(&self) -> Vec<u8> {
        let mut signable_data = bincode::options()
            .with_limit(1024)
            .serialize(&self.data)
            .unwrap();
        signable_data.extend(serialize(&self.metadata).unwrap());
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

    /// Public key as a hex string
    pub fn get_public_key_as_hex(&self) -> String {
        hex::encode(&self.public_key)
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
        data: SampiData,
        metadata: SampiMetadata,
        min_pow_score: Option<u8>,
        keypair: &SampiKeyPair,
        unix_time: Option<i64>,
        threads_count: u64,
    ) -> Result<Self> {
        let mut signable_data = bincode::options().with_limit(1024).serialize(&data)?;
        if signable_data.len() > MAX_DATA_LENGTH + 4 {
            return Err("Data too large".into());
        }

        #[cfg(any(not(target_arch = "wasm32"), target_os = "wasi"))]
        let unix_time =
            unix_time.unwrap_or(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i64);

        #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
        let unix_time = unix_time.unwrap_or(Date::now() as i64);

        let mut s = Sampi {
            unix_time,
            public_key: keypair.keypair.public.to_bytes(),
            signature: [0; 64],
            nonce: 0,
            data,
            metadata,
        };

        signable_data.extend(serialize(&metadata).unwrap());
        signable_data.extend(serialize(&unix_time)?);
        signable_data.extend(keypair.keypair.public.as_bytes());

        let nonce = match min_pow_score {
            Some(min_pow_score) if min_pow_score == 0 => 0,
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
        if self.minimum_pow_score != 0 && s.get_pow_score() < self.minimum_pow_score {
            return false;
        }

        if matches!(self.public_key, Some(public_key) if public_key != s.public_key) {
            return false;
        }

        if s.unix_time < self.minimum_unix_time.unwrap_or(0)
            || s.unix_time > self.maximum_unix_time.unwrap_or_else(i64::max_value)
        {
            return false;
        }

        if let Some(maximum_unix_time_age) = self.maximum_unix_time_age {
            if let Some(current_unix_time) = current_unix_time {
                if current_unix_time - s.unix_time > maximum_unix_time_age {
                    return false;
                }
            } else {
                return false;
            }
        }

        if matches!(&self.data_variant, Some(data_variant) if data_variant != &s.data.variant()) {
            return false;
        }

        let data_length = serialize(&s.data).unwrap().len() as u16;
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
