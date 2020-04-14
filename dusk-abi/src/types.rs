use super::impl_serde_for_array;
// use serde::de::Visitor;
// use serde::ser::SerializeTuple;
use super::Provisioners;
use phoenix_abi::types::{Input, Note, Proof, PublicKey};
use serde::{Deserialize, Serialize};

/// The standard hash type of 32 bytes
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct H256([u8; 32]);

impl H256 {
    /// Return a zero-hash
    pub fn zero() -> Self {
        H256(Default::default())
    }

    /// Create a H256 from a byte slice
    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert!(bytes.len() == 32);
        let mut new = H256::zero();
        new.as_mut().copy_from_slice(bytes);
        new
    }
}

impl AsRef<[u8]> for H256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for H256 {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl core::fmt::Debug for H256 {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "Digest(")?;
        for i in 0..32 {
            write!(f, "{:02x}", self.0[i])?;
        }
        write!(f, ")")
    }
}

const SIGNATURE_BYTES: usize = 64;

/// Standard 64 byte signature type
#[repr(C)]
pub struct Signature([u8; SIGNATURE_BYTES]);

impl Signature {
    /// Create a new signature from a byte slice
    pub fn from_slice(slice: &[u8]) -> Self {
        let mut buf = [0u8; 64];
        buf.copy_from_slice(slice);
        Signature(buf)
    }

    /// Returns a reference to the internal byte array
    pub fn as_array_ref(&self) -> &[u8; 64] {
        &self.0
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsMut<[u8]> for Signature {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl_serde_for_array!(Signature, SIGNATURE_BYTES);

impl core::fmt::Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "Signature(")?;
        for i in 0..64 {
            write!(f, "{:02x}", self.0[i])?;
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum TransferCall {
    Transfer {
        inputs: [Input; Input::MAX],
        notes: [Note; Note::MAX],
        proof: Proof,
    },
    Approve {
        inputs: [Input; Input::MAX],
        notes: [Note; Note::MAX],
        pk: PublicKey,
        value: u64,
        proof: Proof,
    },
    TransferFrom {
        sender: PublicKey,
        recipient: PublicKey,
        value: u64,
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum FeeCall {
    Withdraw {
        sig: Signature,
        address: [u8; 32],
        value: u64,
        pk: PublicKey,
    },
    Distribute {
        total_reward: u64,
        addresses: Provisioners,
        pk: PublicKey,
    },
    GetBalanceAndNonce {
        address: [u8; 32],
    },
}

#[derive(Serialize, Deserialize, Debug)]
pub enum StakingCall {
    Init {
        address: H256,
        pk: PublicKey,
    },
    Stake {
        inputs: [Input; Input::MAX],
        notes: [Note; Note::MAX],
        // proof: Proof,
        pk: PublicKey,
        pk_bls: [u8; 32],
        expiration: u64,
        value: u64,
        current_height: u64,
    },
    Withdraw {
        // proof: Proof,
        pk: PublicKey,
        // sig: Signature,
        current_height: u64,
    },
    Slash {
        pk: PublicKey,
        height: u64,
        step: u8,
        sig1: Signature,
        sig2: Signature,
        msg1: [u8; 32],
        msg2: [u8; 32],
    },
    GetStake {
        pk: PublicKey,
    },
}

#[cfg(feature = "std")]
mod content {
    use std::io::Read;

    use kelvin::{ByteHash, Content, Sink, Source};

    use super::H256;
    use std::io::{self, Write};

    impl<H: ByteHash> Content<H> for H256 {
        fn persist(&mut self, sink: &mut Sink<H>) -> io::Result<()> {
            sink.write_all(&self.0)
        }

        fn restore(source: &mut Source<H>) -> io::Result<Self> {
            let mut h = H256::default();
            source.read_exact(h.as_mut())?;
            Ok(h)
        }
    }
}
