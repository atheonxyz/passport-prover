use crate::error::{self, Error};
use acir::AcirField;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FieldHex(String);

pub const FIELD_HEX_ZERO: &str =
    "0x0000000000000000000000000000000000000000000000000000000000000000";

impl FieldHex {
    pub fn new(hex: impl Into<String>) -> error::Result<Self> {
        let s = hex.into();
        if s.len() <= 2
            || !s.starts_with("0x")
            || !s[2..].chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err(Error::InvalidFieldHex { value: s });
        }
        Ok(Self(s))
    }

    pub(crate) fn new_unchecked(hex: String) -> Self {
        debug_assert!(hex.starts_with("0x") && hex.len() > 2);
        Self(hex)
    }

    pub fn zero() -> Self {
        Self(FIELD_HEX_ZERO.to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for FieldHex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for FieldHex {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<&acir::FieldElement> for FieldHex {
    fn from(f: &acir::FieldElement) -> Self {
        Self::new_unchecked(format!("0x{}", f.to_hex()))
    }
}

impl From<&provekit_common::FieldElement> for FieldHex {
    fn from(f: &provekit_common::FieldElement) -> Self {
        use ark_ff::{BigInteger, PrimeField};
        let bytes = f.into_bigint().to_bytes_be();
        Self::new_unchecked(format!("0x{}", hex::encode(bytes)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    AddDsc,
    AddIdData,
    IntegrityCommit,
    Attest,
}

impl Stage {
    pub fn pkp_filename(&self) -> &'static str {
        match self {
            Self::AddDsc => "t_add_dsc_1850-prover.pkp",
            Self::AddIdData => "t_add_id_data_1850-prover.pkp",
            Self::IntegrityCommit => "t_add_integrity_commit-prover.pkp",
            Self::Attest => "t_attest-prover.pkp",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::AddDsc => "[1/4] t_add_dsc_1850",
            Self::AddIdData => "[2/4] t_add_id_data_1850",
            Self::IntegrityCommit => "[3/4] t_add_integrity_commit",
            Self::Attest => "[4/4] t_attest",
        }
    }

    pub fn number(&self) -> u8 {
        match self {
            Self::AddDsc => 1,
            Self::AddIdData => 2,
            Self::IntegrityCommit => 3,
            Self::Attest => 4,
        }
    }
}

impl fmt::Display for Stage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

pub struct AttestConfig {
    pub r_dg1: FieldHex,
    pub sod_hash: FieldHex,
    pub root: FieldHex,
    pub current_date: u64,
    pub service_scope: FieldHex,
    pub service_subscope: FieldHex,
    pub nullifier_secret: FieldHex,
}

impl AttestConfig {
    pub fn builder() -> AttestConfigBuilder {
        AttestConfigBuilder::default()
    }
}

#[derive(Default)]
pub struct AttestConfigBuilder {
    r_dg1: Option<FieldHex>,
    sod_hash: Option<FieldHex>,
    root: Option<FieldHex>,
    current_date: Option<u64>,
    service_scope: Option<FieldHex>,
    service_subscope: Option<FieldHex>,
    nullifier_secret: Option<FieldHex>,
}

impl AttestConfigBuilder {
    pub fn r_dg1(mut self, v: FieldHex) -> Self {
        self.r_dg1 = Some(v);
        self
    }
    pub fn sod_hash(mut self, v: FieldHex) -> Self {
        self.sod_hash = Some(v);
        self
    }
    pub fn root(mut self, v: FieldHex) -> Self {
        self.root = Some(v);
        self
    }
    pub fn current_date(mut self, v: u64) -> Self {
        self.current_date = Some(v);
        self
    }
    pub fn service_scope(mut self, v: FieldHex) -> Self {
        self.service_scope = Some(v);
        self
    }
    pub fn service_subscope(mut self, v: FieldHex) -> Self {
        self.service_subscope = Some(v);
        self
    }
    pub fn nullifier_secret(mut self, v: FieldHex) -> Self {
        self.nullifier_secret = Some(v);
        self
    }

    pub fn build(self) -> error::Result<AttestConfig> {
        Ok(AttestConfig {
            r_dg1: self
                .r_dg1
                .ok_or(Error::MissingConfigField { field: "r_dg1" })?,
            sod_hash: self
                .sod_hash
                .ok_or(Error::MissingConfigField { field: "sod_hash" })?,
            root: self
                .root
                .ok_or(Error::MissingConfigField { field: "root" })?,
            current_date: self
                .current_date
                .ok_or(Error::MissingConfigField { field: "current_date" })?,
            service_scope: self.service_scope.unwrap_or_else(FieldHex::zero),
            service_subscope: self.service_subscope.unwrap_or_else(FieldHex::zero),
            nullifier_secret: self.nullifier_secret.unwrap_or_else(FieldHex::zero),
        })
    }
}

pub const SALT_STAGE_1: &str = "0x1";
pub const SALT_STAGE_2: &str = "0x2";
