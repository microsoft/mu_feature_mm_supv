use clap::ValueEnum;
use digest::Digest;
use scroll::{ctx, Endian, Pread, Pwrite};
use std::{mem::size_of, path::PathBuf, str::FromStr};

use anyhow::{anyhow, Result};

pub const MANIFEST_V1_FORMAT: &str = r#"
// Algorithm Identifier
const UINT8 ALGO_SHA256 = 0x01;
const UINT8 ALGO_SHA384 = 0x02;
const UINT8 ALGO_SHA512 = 0x03;
const UINT8 ALGO_SM3 = 0x04;

// Algorithm Info structure
typedef struct {
    // Digest Start offset from the start of all digests
    UINT32 DigestOffset;
    // Digest Size
    UINT32 DigestSize;
    // Algorithm ID
    UINT8 AlgorithmId;
    // Reserved (must be zero)
    UINT8 Reserved[7];
} ALGORITHM_INFO;

// The SEA Manifest Version 1, what the manifest looks like in memory.
typedef struct {
    // Structure Signature
    UINT64 StructureSignature;
    // Size of the manifest including digest, excluding the signature size and
    //signature.
    UINT32 ManifestSize;
    // Major Version of the manifest. Only updated if existing fields are
    // changed / reorganized
    UINT16 ManifestVersionMajor;
    // Minor Version of the manifest. Updated if new fields are added to the
    // manifest or reserved fields begin to be used
    UINT16 ManifestVersionMinor;
    // SEA major version associated with the STM firmware binary file.
    UINT16 SeaVersionMajor;
    // Sea minor version associated with the STM firmware binary file.
    UINT16 SeaVersionMinor;
    // Sea patch version associated with the STM firmware binary file.
    UINT16 SeaVersionPatch;
    // Number of algorithm entries in the manifest.
    UINT8 AlgorithmCount;
    // Reserved (must be zero)
    UINT8 Reserved;
    // Offset from the Manifest start to the first algorithm info structure
    UINT32 OffsetToFirstAlgorithmInfo;
    // Offset from the Manifest start to the first algorithm digest
    UINT32 OffsetToFirstDigest;
    // Security Version Number
    UINT64 SecurityVersion;
} SEA_MANIFEST_HEADER_V1;
// Different algorithms used to measure the STM
// ALGORITHM_INFO Algorithms[AlgorithmCount];
// Raw Digest data for each algorithm
// UINT8 DigestData[];
// Size of the appended signature
// UINT32 SignatureSize;
// Signature Data
// UINT8 SignatureData[];
"#;

const MANIFEST_VERSION_MAJOR: u16 = 1;

#[derive(Debug, Clone, ValueEnum)]
pub enum Algorithm {
    Sha256,
    Sha384,
    Sha512,
    Sm3,
}

impl Algorithm {
    pub fn all() -> &'static str {
        "sha256,sha384,sha512,sm3"
    }

    pub fn hash_file(&self, file: &PathBuf) -> Result<Vec<u8>> {
        match self {
            Algorithm::Sha256 => Self::hash_file_core::<sha2::Sha256>(file),
            Algorithm::Sha384 => Self::hash_file_core::<sha2::Sha384>(file),
            Algorithm::Sha512 => Self::hash_file_core::<sha2::Sha512>(file),
            Algorithm::Sm3 => Self::hash_file_core::<sm3::Sm3>(file),
        }
    }

    fn hash_file_core<D: Digest>(file: &PathBuf) -> Result<Vec<u8>> {
        Ok(D::digest(std::fs::read(file)?).to_vec())
    }
}

// Adding additional algorithm support does not constitute a breaking change.
const ALGO_SHA256: u8 = 0x01;
const ALGO_SHA384: u8 = 0x02;
const ALGO_SHA512: u8 = 0x03;
const ALGO_SM3: u8 = 0x04;

const SEA_MANIFEST_V1_HEADER_SIZE: usize = 40;

pub struct SeaManifestV1 {
    structure_signature: u64,
    manifest_size: u32,
    manifest_version_major: u16,
    manifest_version_minor: u16,
    sea_version_major: u16,
    sea_version_minor: u16,
    sea_version_patch: u16,
    algorithm_count: u8,
    reserved: u8,
    offset_to_first_algorithm_info: u32,
    offset_to_first_digest: u32,
    security_version: u64,
    // End Header
    algorithms: Vec<AlgorithmInfo>,
    digest_data: Vec<u8>,
}

impl SeaManifestV1 {
    pub fn build(
        file: PathBuf,
        manifest_version_minor: u16,
        sea_version: String,
        mut security_version: u64,
        algorithms: Vec<Algorithm>,
    ) -> Result<Self> {
        let (major, minor, patch, pre_release) = Self::parse_semantic_version(&sea_version)?;

        if pre_release {
            security_version = 0;
        }

        let algorithm_count = algorithms.len() as u8;
        let (algorithm_info, digest_data) = Self::generate_algorithm_info(&file, algorithms)?;

        let offset_to_first_digest =
            SEA_MANIFEST_V1_HEADER_SIZE + (size_of::<AlgorithmInfo>() * algorithm_count as usize);
        let manifest_size = offset_to_first_digest + digest_data.len();

        Ok(Self {
            structure_signature: u64::from_le_bytes(*b"_SEAMAN_"),
            manifest_size: manifest_size as u32,
            manifest_version_major: MANIFEST_VERSION_MAJOR,
            manifest_version_minor,
            sea_version_major: major,
            sea_version_minor: minor,
            sea_version_patch: patch,
            algorithm_count,
            reserved: 0,
            offset_to_first_algorithm_info: SEA_MANIFEST_V1_HEADER_SIZE as u32,
            offset_to_first_digest: offset_to_first_digest as u32,
            security_version,
            algorithms: algorithm_info,
            digest_data,
        })
    }

    pub fn size(&self) -> usize {
        self.manifest_size as usize
    }

    fn generate_algorithm_info(
        file: &PathBuf,
        algorithms: Vec<Algorithm>,
    ) -> Result<(Vec<AlgorithmInfo>, Vec<u8>)> {
        let mut digest_data = Vec::new();
        let mut algorithms_info = Vec::new();
        let mut digest_offset = 0;

        for algorithm in algorithms {
            let digest = algorithm.hash_file(file)?;
            let digest_size = digest.len() as u32;

            digest_data.extend(digest);
            algorithms_info.push(AlgorithmInfo {
                algorithm_id: match algorithm {
                    Algorithm::Sha256 => ALGO_SHA256,
                    Algorithm::Sha384 => ALGO_SHA384,
                    Algorithm::Sha512 => ALGO_SHA512,
                    Algorithm::Sm3 => ALGO_SM3,
                },
                digest_offset,
                digest_size,
                reserved: [0; 7],
            });

            digest_offset += digest_size;
        }

        Ok((algorithms_info, digest_data))
    }

    fn parse_semantic_version(mut version: &str) -> Result<(u16, u16, u16, bool)> {
        if version.chars().filter(|&c| c == '.').count() != 2 {
            return Err(anyhow!("Version [{}] is not in the format x.y.z", &version));
        }

        let pre_release = if version.contains('-') {
            version = version.split('-').next().unwrap();
            true
        } else {
            false
        };

        let mut parts = version.split('.').map(u16::from_str);

        // The first unwrap is an option that is guaranteed to be Some because the version has 3 parts.
        Ok((
            parts
                .next()
                .unwrap()
                .map_err(|err| anyhow!("Failed to parse Version [{}]. Err: [{}]", version, err))?,
            parts
                .next()
                .unwrap()
                .map_err(|err| anyhow!("Failed to parse Version [{}]. Err: [{}]", version, err))?,
            parts
                .next()
                .unwrap()
                .map_err(|err| anyhow!("Failed to parse Version [{}]. Err: [{}]", version, err))?,
            pre_release,
        ))
    }
}

impl ctx::TryIntoCtx<Endian> for &SeaManifestV1 {
    type Error = scroll::Error;

    fn try_into_ctx(self, this: &mut [u8], le: Endian) -> Result<usize, Self::Error> {
        let mut offset = 0;

        this.gwrite_with(self.structure_signature, &mut offset, le)?;
        this.gwrite_with(self.manifest_size, &mut offset, le)?;
        this.gwrite_with(self.manifest_version_major, &mut offset, le)?;
        this.gwrite_with(self.manifest_version_minor, &mut offset, le)?;
        this.gwrite_with(self.sea_version_major, &mut offset, le)?;
        this.gwrite_with(self.sea_version_minor, &mut offset, le)?;
        this.gwrite_with(self.sea_version_patch, &mut offset, le)?;
        this.gwrite_with(self.algorithm_count, &mut offset, le)?;
        this.gwrite_with(self.reserved, &mut offset, le)?;
        this.gwrite_with(self.offset_to_first_algorithm_info, &mut offset, le)?;
        this.gwrite_with(self.offset_to_first_digest, &mut offset, le)?;
        this.gwrite_with(self.security_version, &mut offset, le)?;
        debug_assert!(offset == self.offset_to_first_algorithm_info as usize);

        for algorithm in self.algorithms.iter() {
            this.gwrite_with(algorithm, &mut offset, le)?;
        }
        debug_assert!(offset == self.offset_to_first_digest as usize);
        this.gwrite_with(self.digest_data.as_slice(), &mut offset, ())?;
        debug_assert!(offset == self.manifest_size as usize);

        Ok(offset)
    }
}

#[derive(Pread, Pwrite)]
struct AlgorithmInfo {
    digest_offset: u32,
    digest_size: u32,
    algorithm_id: u8,
    reserved: [u8; 7],
}
