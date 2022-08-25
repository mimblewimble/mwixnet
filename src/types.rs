use crate::secp::{self, RangeProof, SecretKey};

use grin_core::core::FeeFields;
use grin_core::ser::{self, Readable, Reader, Writeable, Writer};
use serde::{Deserialize, Serialize};

const CURRENT_VERSION: u8 = 0;

/// Writes an optional value as '1' + value if Some, or '0' if None
pub fn write_optional<O: Writeable, W: Writer>(
	writer: &mut W,
	o: &Option<O>,
) -> Result<(), ser::Error> {
	match &o {
		Some(o) => {
			writer.write_u8(1)?;
			o.write(writer)?;
		}
		None => writer.write_u8(0)?,
	};
	Ok(())
}

/// Reads an optional value as '1' + value if Some, or '0' if None
pub fn read_optional<O: Readable, R: Reader>(reader: &mut R) -> Result<Option<O>, ser::Error> {
	let o = if reader.read_u8()? == 0 {
		None
	} else {
		Some(O::read(reader)?)
	};
	Ok(o)
}

// todo: Belongs in Onion
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Payload {
	pub excess: SecretKey,
	pub fee: FeeFields,
	pub rangeproof: Option<RangeProof>,
}

impl Payload {
	pub fn deserialize(bytes: &Vec<u8>) -> Result<Payload, ser::Error> {
		let payload: Payload = ser::deserialize_default(&mut &bytes[..])?;
		Ok(payload)
	}

	#[cfg(test)]
	pub fn serialize(&self) -> Result<Vec<u8>, ser::Error> {
		let mut vec = vec![];
		ser::serialize_default(&mut vec, &self)?;
		Ok(vec)
	}
}

impl Readable for Payload {
	fn read<R: Reader>(reader: &mut R) -> Result<Payload, ser::Error> {
		let version = reader.read_u8()?;
		if version != CURRENT_VERSION {
			return Err(ser::Error::UnsupportedProtocolVersion);
		}

		let excess = secp::read_secret_key(reader)?;
		let fee = FeeFields::try_from(reader.read_u64()?).map_err(|_| ser::Error::CorruptedData)?;
		let rangeproof = read_optional(reader)?;
		Ok(Payload {
			excess,
			fee,
			rangeproof,
		})
	}
}

impl Writeable for Payload {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_u8(CURRENT_VERSION)?;
		writer.write_fixed_bytes(&self.excess)?;
		writer.write_u64(self.fee.into())?;
		write_optional(writer, &self.rangeproof)?;
		Ok(())
	}
}
