use std::io;

pub const VERSION: u8 = 1;
pub const MAX_PACKET: usize = 65_535;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    Hello(u8),
    Data(Vec<u8>),
    KeepAlive,
    Disconnect,
}

impl Packet {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        let mut result = Vec::new();

        match self {
            Self::Hello(version) => {
                result.extend_from_slice(&[1, *version]);
            }
            Self::Data(data) => {
                if data.len() > MAX_PACKET {
                    return Err(invalid("Packet too large"));
                }

                result.push(2);
                result.extend_from_slice(
                    &(data.len() as u32).to_be_bytes()
                );
                result.extend_from_slice(data);
            }
            Self::KeepAlive => result.push(3),
            Self::Disconnect => result.push(4),
        }

        Ok(result)
    }

    pub fn decode(input: &[u8]) -> io::Result<Self> {
        let Some((&kind, rest)) = input.split_first() else {
            return Err(invalid("Empty packet"));
        };

        match kind {
            1 if rest.len() == 1 => {
                Ok(Self::Hello(rest[0]))
            }
            2 if rest.len() >= 4 => {
                let size = u32::from_be_bytes(
                    rest[..4].try_into().unwrap()
                ) as usize;

                if size > MAX_PACKET || rest.len() - 4 != size {
                    return Err(invalid("Invalid data length"));
                }

                Ok(Self::Data(rest[4..].to_vec()))
            }
            3 if rest.is_empty() => Ok(Self::KeepAlive),
            4 if rest.is_empty() => Ok(Self::Disconnect),
            _ => Err(invalid("Invalid packet")),
        }
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        message.to_owned(),
    )
}