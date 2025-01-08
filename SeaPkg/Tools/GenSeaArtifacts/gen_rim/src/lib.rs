//! A library containing necessary data structures representing CBOR formatted
//! COSE objects.
//!
//! Data structures are defined here:
//! - https://www.rfc-editor.org/rfc/rfc9393.html
//! - https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml
//!
//! ## License
//!
//! Copyright (c) Microsoft Corporation.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent
//!
#![no_std]
use core::str::FromStr;

use minicbor::{bytes::ByteVec, encode::Write, Decode, Decoder, Encode, Encoder};
extern crate alloc;
use alloc::{string::String, vec::Vec};

/// An alias of a Byte String.
///
/// This is used to first encode an object as a CBOR bytes array and then
/// encode the bytes as a CBOR byte string.
///
/// https://www.rfc-editor.org/rfc/rfc9052.html#section-1.4-3.6
pub struct Bstr<Payload>(pub Payload);

impl<Payload> AsRef<Payload> for Bstr<Payload> {
    fn as_ref(&self) -> &Payload {
        &self.0
    }
}

impl<Payload> Bstr<Payload> {
    pub fn new(payload: Payload) -> Self {
        Bstr { 0: payload }
    }
}

impl<Ctx, Payload: Encode<Ctx>> Encode<Ctx> for Bstr<Payload> {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut Ctx,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        let mut buffer: Vec<u8> = Vec::new();
        let mut encoder = Encoder::new(&mut buffer);
        match self.as_ref().encode(&mut encoder, ctx) {
            Ok(_) => (),
            Err(_) => return Err(minicbor::encode::Error::message("Failed to encode payload")),
        }
        e.bytes(&buffer)?;
        Ok(())
    }
}

impl<'bytes, Ctx, Payload: Decode<'bytes, Ctx>> Decode<'bytes, Ctx> for Bstr<Payload> {
    fn decode(
        d: &mut Decoder<'bytes>,
        ctx: &mut Ctx,
    ) -> Result<Bstr<Payload>, minicbor::decode::Error> {
        let bytes = d.bytes()?;
        let mut decoder = Decoder::new(&bytes);
        let payload = Payload::decode(&mut decoder, ctx)?;
        Ok(Bstr::new(payload))
    }
}

/// COSE_Sign1-coswid<payload>
/// https://www.rfc-editor.org/rfc/rfc9393.html#name-signed-coswid-tags
#[derive(Encode, Decode)]
#[cbor(array)]
#[cbor(tag(18))]
pub struct CoseSign1<Payload> {
    #[n(0)]
    /// protected-signed-coswid-header
    pub protected: Bstr<ProtectedHeader>,
    #[n(1)]
    /// unprotected-signed-coswid-header
    pub unprotected: UnprotectedHeader,
    #[n(2)]
    /// The payload to be signed
    pub payload: Bstr<Payload>,
    #[n(3)]
    /// The signature of the payload
    pub signature: ByteVec,
}

impl<Payload> CoseSign1<Payload> {
    pub fn new<S>(
        protected: ProtectedHeader,
        unprotected: UnprotectedHeader,
        payload: Payload,
        signature: S,
    ) -> Self
    where
        S: Into<ByteVec>,
    {
        CoseSign1 {
            protected: Bstr::new(protected),
            unprotected,
            payload: Bstr::new(payload),
            signature: signature.into(),
        }
    }
}

/// Sig_structure<payload>
/// https://www.rfc-editor.org/rfc/rfc9052.html#name-signing-and-verification-pr
#[derive(Encode, Decode)]
#[cbor(array)]
pub struct SigStructure<Payload> {
    #[n(0)]
    pub context: String,
    #[n(1)]
    pub body_protected: ProtectedHeader,
    #[n(2)]
    pub sign_protected: Option<SignProtected>,
    #[n(3)]
    pub external_aad: ByteVec,
    #[n(4)]
    pub payload: Bstr<Payload>,
}

impl<Payload> SigStructure<Payload> {
    pub fn new(payload: Payload, body_protected: ProtectedHeader) -> Self {
        Self {
            context: "Signature1".into(),
            body_protected,
            sign_protected: None,
            external_aad: Vec::new().into(),
            payload: Bstr::new(payload),
        }
    }
}

/// sign-protected
/// Protected attributes
/// https://www.rfc-editor.org/rfc/rfc9052.html#name-signing-and-verification-pr
#[derive(Encode, Decode)]
#[cbor(map)]
pub struct SignProtected;

/// protected-signed-coswid-header
/// https://www.rfc-editor.org/rfc/rfc9393.html#name-signed-coswid-tags
/// Use the following for the algorithm_identifier:
/// https://www.iana.org/assignments/named-information/named-information.xhtml
#[derive(Encode, Decode)]
#[cbor(map)]
pub struct ProtectedHeader {
    #[n(1)]
    /// The algorithm used to sign the payload
    pub algorithm_identifier: i16,
    /// Should always be "application/swid+cbor"
    #[n(3)]
    pub content_type: String,
}

impl ProtectedHeader {
    pub fn new<S>(algorithm_identifier: i16, content_type: S) -> Self
    where
        S: Into<String>,
    {
        ProtectedHeader {
            algorithm_identifier,
            content_type: content_type.into(),
        }
    }
}

/// A unprotected-signed-coswid-header as defined in rcfc9393
/// https://www.rfc-editor.org/rfc/rfc9393.html#name-signed-coswid-tags
#[derive(Encode, Decode)]
#[cbor(map)]
pub struct UnprotectedHeader {}

impl UnprotectedHeader {
    pub fn new() -> Self {
        UnprotectedHeader {}
    }
}

/// A concise-swid-tag as defined in rcfc9393
/// https://www.rfc-editor.org/rfc/rfc9393.html#name-the-concise-swid-tag-map
#[derive(Encode, Decode)]
#[cbor(map)]
#[cbor(tag(1398229316))]
pub struct ConciseSwidTag<Payload> {
    #[n(0)]
    /// The UUID of the tag
    pub tag_id: ByteVec,
    #[n(12)]
    /// Represents the release version of the tag
    pub tag_version: u32,
    #[n(8)]
    /// If the tag identifies and describes an installable software component before installation
    pub corpus: Option<bool>,
    #[n(9)]
    /// If the tag identifies and describes an installed patch
    pub patch: Option<bool>,
    #[n(11)]
    /// If the tag is providing additional information to be associated with another referenced SWID or CoSWID tag
    pub supplemental: Option<bool>,
    #[n(1)]
    /// colloquial software name
    pub software_name: String,
    #[n(13)]
    /// colloquial version
    pub software_version: Option<String>,
    #[n(14)]
    /// Versioning scheme
    pub version_scheme: Option<String>,
    #[n(10)]
    /// Hint to the tag consumer to understand what target platform this tag applies to
    pub media: Option<String>,
    #[n(5)]
    /// Map of key/value data pairs
    pub software_meta: Option<SoftwareMetaEntry>,
    #[n(2)]
    /// Provides information about the organization(s) that created the tag
    pub entity: Option<EntityEntry>,
    #[n(4)]
    /// Establish a relationship between the tag and another item
    pub link: Option<LinkEntry>,
    #[n(6)]
    /// The payload, mutual exclusive with evidence
    pub payload: Option<Payload>,
    #[n(3)]
    /// The evidence, mutual exclusive with payload
    pub evidence: Option<Payload>,
}

impl<Payload> ConciseSwidTag<Payload> {
    pub fn new<S1, S2>(tag_id: S1, tag_version: u32, software_name: S2) -> Self
    where
        S1: Into<String>,
        S2: Into<String>,
    {
        ConciseSwidTag {
            tag_id: ByteVec::from(
                uuid::Uuid::from_str(&tag_id.into())
                    .unwrap()
                    .to_bytes_le()
                    .to_vec(),
            ),
            tag_version,
            corpus: None,
            patch: None,
            supplemental: None,
            software_name: software_name.into(),
            software_version: None,
            version_scheme: None,
            media: None,
            software_meta: None,
            entity: None,
            link: None,
            payload: None,
            evidence: None,
        }
    }
    pub fn with_corpus(mut self, corpus: bool) -> Self {
        self.corpus = Some(corpus);
        self
    }

    pub fn with_patch(mut self, patch: bool) -> Self {
        self.patch = Some(patch);
        self
    }

    pub fn with_supplemental(mut self, supplemental: bool) -> Self {
        self.supplemental = Some(supplemental);
        self
    }

    pub fn with_software_version<S: Into<String>>(mut self, software_version: S) -> Self {
        self.software_version = Some(software_version.into());
        self
    }

    pub fn with_version_scheme<S: Into<String>>(mut self, version_scheme: S) -> Self {
        self.version_scheme = Some(version_scheme.into());
        self
    }

    pub fn with_media<S: Into<String>>(mut self, media: S) -> Self {
        self.media = Some(media.into());
        self
    }

    pub fn with_software_meta(mut self, software_meta: SoftwareMetaEntry) -> Self {
        self.software_meta = Some(software_meta);
        self
    }

    pub fn with_entity(mut self, entity: EntityEntry) -> Self {
        self.entity = Some(entity);
        self
    }

    pub fn with_link(mut self, link: LinkEntry) -> Self {
        self.link = Some(link);
        self
    }

    pub fn with_payload(mut self, payload: Payload) -> Self {
        assert!(self.evidence.is_none());
        self.payload = Some(payload);
        self
    }

    pub fn with_evidence(mut self, evidence: Payload) -> Self {
        assert!(self.payload.is_none());
        self.evidence = Some(evidence);
        self
    }
}

#[derive(Encode, Decode)]
#[cbor(map)]
/// A Software Meta Entry as defined in rcfc9393
/// https://www.rfc-editor.org/rfc/rfc9393.html#name-the-software-meta-entry-map
pub struct SoftwareMetaEntry {
    #[n(43)]
    /// How the software is activated - trial, licensed, etc
    activation_status: Option<String>,
    #[n(44)]
    /// The sales, licensing, or marketing channel the software component has been targeted for
    channel_type: Option<String>,
    #[n(45)]
    /// Informational or colloquial version
    colloquial_version: Option<String>,
    #[n(46)]
    /// Detailed description of the software component
    description: Option<String>,
    #[n(47)]
    /// A value representing a functional variation of the code base
    edition: Option<String>,
    #[n(48)]
    /// Whether entitlement data is required for the software component
    entitlement_data_required: Option<bool>,
    #[n(49)]
    /// A unique identifier for the entitlement data
    entitlement_key: Option<String>,
    #[n(50)]
    /// The name of the tool that generated the SWID tag
    generator: Option<String>,
    #[n(51)]
    /// A unique identifier for a group of software components to tie them together
    persistent_id: Option<String>,
    #[n(52)]
    /// Basic name for the software component
    product: Option<String>,
    #[n(53)]
    /// Overall Family of products the software component belongs to
    product_family: Option<String>,
    #[n(54)]
    /// Informational or colloquial release version of the software
    revision: Option<String>,
    #[n(55)]
    /// A short description of the software component
    summary: Option<String>,
    #[n(56)]
    /// The UNSPSC code for the software component
    unspsc_code: Option<String>,
    #[n(57)]
    /// A CDDL socket that can be used to extend the software-meta-entry-group
    unspsc_version: Option<String>,
}

impl SoftwareMetaEntry {
    pub fn new() -> Self {
        SoftwareMetaEntry {
            activation_status: None,
            channel_type: None,
            colloquial_version: None,
            description: None,
            edition: None,
            entitlement_data_required: None,
            entitlement_key: None,
            generator: None,
            persistent_id: None,
            product: None,
            product_family: None,
            revision: None,
            summary: None,
            unspsc_code: None,
            unspsc_version: None,
        }
    }

    pub fn with_colloquial_version<S: Into<String>>(mut self, colloquial_version: S) -> Self {
        self.colloquial_version = Some(colloquial_version.into());
        self
    }

    pub fn with_edition<S: Into<String>>(mut self, edition: S) -> Self {
        self.edition = Some(edition.into());
        self
    }

    pub fn with_product<S: Into<String>>(mut self, product: S) -> Self {
        self.product = Some(product.into());
        self
    }

    pub fn with_revision<S: Into<String>>(mut self, revision: S) -> Self {
        self.revision = Some(revision.into());
        self
    }
}

#[derive(Encode, Decode)]
#[cbor(map)]
/// A Entity Entry as defined in rcfc9393
/// https://www.rfc-editor.org/rfc/rfc9393.html#name-the-entity-entry-map
pub struct EntityEntry {
    #[n(31)]
    /// Textual name of the organizational entity claiming the roles
    entity_name: String,
    #[n(32)]
    /// Registration ID, must be a URI
    reg_id: Option<String>,
    #[n(33)]
    /// A list of roles the entity plays
    role: Vec<String>,
    #[n(34)]
    /// A Hash of the signing entity's public key certificate
    thumbprint: Option<String>,
}

impl EntityEntry {
    pub fn new<S: Into<String>>(entity_name: S) -> Self {
        EntityEntry {
            entity_name: entity_name.into(),
            reg_id: None,
            role: Vec::new(),
            thumbprint: None,
        }
    }

    pub fn with_role<S: Into<String>>(mut self, role: S) -> Self {
        self.role.push(role.into());
        self
    }

    pub fn with_reg_id<S: Into<String>>(mut self, reg_id: S) -> Self {
        self.reg_id = Some(reg_id.into());
        self
    }
}

#[derive(Encode, Decode)]
#[cbor(map)]
/// A Link Entry as defined in rcfc9393
/// https://www.rfc-editor.org/rfc/rfc9393.html#name-the-link-entry-map
pub struct LinkEntry {
    #[n(37)]
    /// Path to the installation media when [LinkEntry::rel] is "installationmedia"
    artifact: Option<String>,
    #[n(38)]
    /// a URI reference for the resource
    href: String,
    #[n(10)]
    /// A hint to the type of media
    media: Option<String>,
    #[n(39)]
    /// Indicates degree of ownership of the resource
    ownership: Option<String>,
    #[n(40)]
    /// Identifies the relationship between this CoSWID and the targt resource identified by href
    rel: String,
    #[n(41)]
    /// A hint to the type of media
    media_type: Option<String>,
    #[n(42)]
    /// If the referenced resource must be installed.
    r#use: Option<String>,
}

impl LinkEntry {
    pub fn new<S1, S2>(href: S1, rel: S2) -> LinkEntry
    where
        S1: Into<String>,
        S2: Into<String>,
    {
        LinkEntry {
            artifact: None,
            href: href.into(),
            media: None,
            ownership: None,
            rel: rel.into(),
            media_type: None,
            r#use: None,
        }
    }
}

pub struct CoseMac0 {}

#[derive(Encode, Decode)]
#[cbor(array)]
/// A COSE Algorithm payload
/// https://www.rfc-editor.org/rfc/rfc9393.html#section-2.9.1
/// algorithm ID should be from:
/// https://www.iana.org/assignments/named-information/named-information.xhtml
pub struct CoseAlgorithmPayload {
    #[n(0)]
    /// The algorithm identifier.
    pub algorithm_id: i16,
    #[n(1)]
    /// The digest of the file.
    pub digest: ByteVec,
}

#[derive(Encode, Decode)]
#[cbor(map)]
/// A File Measurement payload
pub struct FileMeasurement {
    #[n(23)]
    /// The path to the file being measured.
    file: String,
    #[n(24)]
    /// A canonical name for the entry.
    name: String,
    #[n(20)]
    /// The size of the file in bytes.
    size: u64,
    #[n(7)]
    /// The algorithm and digest of the file.
    alg: CoseAlgorithmPayload,
}

impl FileMeasurement {
    pub fn new<S1, S2, S3>(file: S1, name: S2, size: u64, algorithm: i16, digest: S3) -> Self
    where
        S1: Into<String>,
        S2: Into<String>,
        S3: Into<ByteVec>,
    {
        FileMeasurement {
            file: file.into(),
            name: name.into(),
            size,
            alg: CoseAlgorithmPayload {
                algorithm_id: algorithm,
                digest: digest.into(),
            },
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const MAJOR_TYPE: u8 = 0b0100_0000;
    const BYTE_1: u8 = 0b0001_1000;
    const BYTE_2: u8 = 0b0001_1001;
    const BYTE_4: u8 = 0b0001_1010;

    #[test]
    fn test_bstr_encoded_properly_payload_len_less_than_limit_direct() {
        // payload lenght less that LIMIT_DIRECT
        let payload = "*".repeat(10);
        let payload_len = payload.len() as u8 + 1; // +1 for the cbor string header

        let bstr = Bstr::new(payload.clone());

        // bstr buffer
        let mut bstr_buf = Vec::new();
        let mut encoder = Encoder::new(&mut bstr_buf);
        bstr.encode(&mut encoder, &mut ()).unwrap();

        // str buffer
        let mut str_buf = Vec::new();
        let mut encoder = Encoder::new(&mut str_buf);
        payload.encode(&mut encoder, &mut ()).unwrap();

        assert_eq!(bstr_buf[0], MAJOR_TYPE | payload_len);
        assert_eq!(bstr_buf[1..], str_buf);
    }

    #[test]
    fn test_bstr_encoded_properly_payload_len_less_than_limit_1_byte() {
        // payload lenght less that LIMIT_BYTE_1
        let payload = "*".repeat(0xf0);
        let payload_len = payload.len() as u8 + 2; // + 2 for the cbor string header

        let bstr = Bstr::new(payload.clone());

        // bstr buffer
        let mut bstr_buf = Vec::new();
        let mut encoder = Encoder::new(&mut bstr_buf);
        bstr.encode(&mut encoder, &mut ()).unwrap();

        // str buffer
        let mut str_buf = Vec::new();
        let mut encoder = Encoder::new(&mut str_buf);
        payload.encode(&mut encoder, &mut ()).unwrap();

        assert_eq!(bstr_buf[0], MAJOR_TYPE | BYTE_1);
        assert_eq!(bstr_buf[1], payload_len.to_be_bytes()[0]);
        assert_eq!(bstr_buf[2..], str_buf);
    }

    #[test]
    fn test_bstr_encoded_properly_payload_len_less_than_limit_2_byte() {
        // payload lenght less that LIMIT_BYTE_2
        let payload = "*".repeat(0xfff0);
        let payload_len = payload.len() as u16 + 3; // + 3 for the cbor string header

        let bstr = Bstr::new(payload.clone());

        // bstr buffer
        let mut bstr_buf = Vec::new();
        let mut encoder = Encoder::new(&mut bstr_buf);
        bstr.encode(&mut encoder, &mut ()).unwrap();

        // str buffer
        let mut str_buf = Vec::new();
        let mut encoder = Encoder::new(&mut str_buf);
        payload.encode(&mut encoder, &mut ()).unwrap();

        assert_eq!(bstr_buf[0], MAJOR_TYPE | BYTE_2);
        assert_eq!(bstr_buf[1..2], payload_len.to_be_bytes()[0..1]);
        assert_eq!(bstr_buf[3..], str_buf);
    }

    #[test]
    fn test_bstr_encoded_properly_payload_len_less_than_limit_4_byte() {
        // payload lenght less that LIMIT_BYTE_2
        let payload = "*".repeat(0xffff_fff0);
        let payload_len = payload.len() as u32 + 3; // + 3 for the cbor string header

        let bstr = Bstr::new(payload.clone());

        // bstr buffer
        let mut bstr_buf = Vec::new();
        let mut encoder = Encoder::new(&mut bstr_buf);
        bstr.encode(&mut encoder, &mut ()).unwrap();

        // str buffer
        let mut str_buf = Vec::new();
        let mut encoder = Encoder::new(&mut str_buf);
        payload.encode(&mut encoder, &mut ()).unwrap();

        assert_eq!(bstr_buf[0], MAJOR_TYPE | BYTE_4);
        assert_eq!(bstr_buf[1..4], payload_len.to_be_bytes()[0..3]);
        assert_eq!(bstr_buf[5..], str_buf);
    }

    #[test]
    fn test_bstr_encoded_properly_decodes_with_payload_len_less_than_limit_direct() {
        let payload = "*".repeat(10);

        let bstr = Bstr::new(payload.clone());

        let mut buffer = Vec::new();
        let mut encoder = Encoder::new(&mut buffer);
        bstr.encode(&mut encoder, &mut ()).unwrap();

        let mut decoder = Decoder::new(&buffer);
        let decoded_bstr: Bstr<String> = Bstr::decode(&mut decoder, &mut ()).unwrap();
        assert_eq!(decoded_bstr.payload, payload);
    }
}
