use crate::error::{ErrorKind, Result};
use crate::secp::{Commitment, PublicKey, RangeProof, SecretKey, Secp256k1};
use crate::ser::{self, BinReader, Readable, Reader, Writeable, Writer};

use grin_core::core::FeeFields;
use grin_util::{self, ToHex};
use serde::{Deserialize, Serialize};
use serde::ser::SerializeStruct;
use std::fmt;
use std::io::Cursor;

pub type RawBytes = Vec<u8>;

const CURRENT_VERSION : u8 = 0;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Payload {
    pub excess: SecretKey,
    pub fee: FeeFields,
    pub rangeproof: Option<RangeProof>,
}

impl Readable for Payload {
    fn read<R: Reader>(reader: &mut R) -> Result<Payload> {
        let version = reader.read_u8()?;
        if version != CURRENT_VERSION {
            return Err(ErrorKind::UnsupportedPayload.into());
        }

        let excess = SecretKey::read(reader)?;
        let fee = FeeFields::try_from(reader.read_u64()?)?;
        let rangeproof = if reader.read_u8()? == 0 {
            None
        } else {
            Some(RangeProof::read(reader)?)
        };

        let payload = Payload {
            excess: excess,
            fee: fee,
            rangeproof: rangeproof
        };
        Ok(payload)
    }
}

impl Writeable for Payload {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<()> {
        writer.write_u8(CURRENT_VERSION)?;
        writer.write_fixed_bytes(&self.excess)?;
        writer.write_u64(self.fee.into())?;

        match &self.rangeproof {
            Some(proof) => {
                writer.write_u8(1)?;
                proof.write(writer)?;
            },
            None => writer.write_u8(0)?,
        };

        Ok(())
    }
}

pub fn serialize_payload(payload: &Payload) -> Result<Vec<u8>> {
    ser::ser_vec(&payload)
}

pub fn deserialize_payload(bytes: &Vec<u8>) -> Result<Payload> {
    let mut cursor = Cursor::new(&bytes);
    let mut reader = BinReader::new(&mut cursor);
    Payload::read(&mut reader)
}

pub struct Hop {
    pub pubkey: PublicKey,
    pub payload: Payload,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Onion {
    pub ephemeral_pubkey: PublicKey,
    pub commit: Commitment,
    pub enc_payloads: Vec<RawBytes>,
}

impl serde::ser::Serialize for Onion {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let mut state = serializer.serialize_struct("Onion", 3)?;

        let secp = Secp256k1::new();
        state.serialize_field("pubkey", &self.ephemeral_pubkey.serialize_vec(&secp, true).to_hex())?;
        state.serialize_field("commit", &self.commit.to_hex())?;

        let hex_payloads: Vec<String> = self.enc_payloads.iter().map(|v| v.to_hex()).collect();
        state.serialize_field("data", &hex_payloads)?;
        state.end()
    }
}

impl<'de> serde::de::Deserialize<'de> for Onion {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Pubkey,
            Commit,
            Data
        }

        struct OnionVisitor;

        impl<'de> serde::de::Visitor<'de> for OnionVisitor {
            type Value = Onion;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an Onion")
            }

            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut pubkey = None;
                let mut commit = None;
                let mut data = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Pubkey => {
                            let val: String = map.next_value()?;
                            let vec = grin_util::from_hex(&val).map_err(serde::de::Error::custom)?;
                            let secp = Secp256k1::new();
                            pubkey = Some(PublicKey::from_slice(&secp, &vec[..]).map_err(serde::de::Error::custom)?);
                        }
                        Field::Commit => {
                            let val: String = map.next_value()?;
                            let vec = grin_util::from_hex(&val).map_err(serde::de::Error::custom)?;
                            commit = Some(Commitment::from_vec(vec));
                        }
                        Field::Data => {
                            let val: Vec<String> = map.next_value()?;
                            let mut vec: Vec<Vec<u8>> = Vec::new();
                            for hex in val {
                                vec.push(grin_util::from_hex(&hex).map_err(serde::de::Error::custom)?);
                            }
                            data = Some(vec);
                        }
                    }
                }

                Ok(Onion {
                    ephemeral_pubkey: pubkey.unwrap(),
                    commit: commit.unwrap(),
                    enc_payloads: data.unwrap(),
                })
            }
        }

        const FIELDS: &[&str] = &[
            "pubkey",
            "commit",
            "data"
        ];
        deserializer.deserialize_struct("Onion", &FIELDS, OnionVisitor)
    }
}