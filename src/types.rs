use crate::error::{Result, StdResult};
use crate::secp::{self, RangeProof, SecretKey};

use grin_core::core::FeeFields;
use grin_core::ser::{self, Readable, Reader, Writeable, Writer};
use serde::{Deserialize, Serialize};

const CURRENT_VERSION: u8 = 0;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Payload {
	pub excess: SecretKey,
	pub fee: FeeFields,
	pub rangeproof: Option<RangeProof>,
}

impl Payload {
	pub fn deserialize(bytes: &Vec<u8>) -> Result<Payload> {
		let payload: Payload = ser::deserialize_default(&mut &bytes[..])?;
		Ok(payload)
	}

	#[cfg(test)]
	pub fn serialize(&self) -> Result<Vec<u8>> {
		let mut vec = vec![];
		ser::serialize_default(&mut vec, &self)?;
		Ok(vec)
	}
}

impl Readable for Payload {
	fn read<R: Reader>(reader: &mut R) -> StdResult<Payload, ser::Error> {
		let version = reader.read_u8()?;
		if version != CURRENT_VERSION {
			return Err(ser::Error::UnsupportedProtocolVersion);
		}

		let excess = secp::read_secret_key(reader)?;
		let fee = FeeFields::try_from(reader.read_u64()?).map_err(|_| ser::Error::CorruptedData)?;
		let rangeproof = if reader.read_u8()? == 0 {
			None
		} else {
			Some(RangeProof::read(reader)?)
		};

		let payload = Payload {
			excess,
			fee,
			rangeproof,
		};
		Ok(payload)
	}
}

impl Writeable for Payload {
	fn write<W: Writer>(&self, writer: &mut W) -> StdResult<(), ser::Error> {
		writer.write_u8(CURRENT_VERSION)?;
		writer.write_fixed_bytes(&self.excess)?;
		writer.write_u64(self.fee.into())?;

		match &self.rangeproof {
			Some(proof) => {
				writer.write_u8(1)?;
				proof.write(writer)?;
			}
			None => writer.write_u8(0)?,
		};

		Ok(())
	}
}
