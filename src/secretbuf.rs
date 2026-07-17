//! What does this module solves?
//! We want to use fix length arrays in the heap to store passwords and secret notes. This allows us to control the memory
//! to guarantee that there are not string reallocation. If a string grew beyond it's initially allocated buffer it could lead
//! to memory getting freed but not zeroed out (In other words, we want to "heap pin" the value).
//!
//! The downside to all this is that we create copies when we want to display those values, and we still create string when the value
//! is taken out of these structs (presumably to display in the UI). This mean the value is in memory twice and the string could
//! still be miss-handled by the end user. Nevertheless, it establishes a good base on which we could built improvements later on.
//!
//! (NOTE: I understand crates exists to solves this problem, but the point of this project is to learn rust, and this felt like a
//! learning opportunity. With that in mind, I supposed we *could* create a custom container, instead of Box, with a
//! customer allocator to force allocation on the heap. But at some point it's little bit above the scope of this project,
//! which is meant to be Rust 101. Keeping a note here for future potential improvement.)

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::Error;

#[derive(ZeroizeOnDrop)]
pub struct SecretBuf(Box<[u8]>);

// TODO This does not take memory swapping into account. We need to look into mlock for rust...
impl SecretBuf {
    pub fn new(note: Zeroizing<String>) -> Result<Self, Error> {
        let bytes = note.as_bytes();
        let note_buf: Box<[u8]> = Box::from(bytes);
        Ok(SecretBuf(note_buf))
    }

    pub fn as_str(&self) -> Result<Zeroizing<String>, Error> {
        let s = std::str::from_utf8(&self.0[..]).map_err(|_| Error::CorruptedSecret)?;
        Ok(Zeroizing::new(s.to_string()))
    }
}

// Won't leak actual secret to logs and such
impl fmt::Debug for SecretBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "**********") // always 10 stars
    }
}

impl Zeroize for SecretBuf {
    fn zeroize(&mut self) {
        self.0.iter_mut().for_each(|b| *b = 0);
    }
}

impl Serialize for SecretBuf {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0.as_ref())
    }
}

impl<'de> Deserialize<'de> for SecretBuf {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Future-Self Note: Create Box to copy data. Alternative is using into_boxed_slice() but that means not wrapping the vec
        // in Zeroizing because into_boxed_slice() consumes itself. This way Zeroizing wipes the Vec on drop at end of function.
        let bytes = Zeroizing::new(<Vec<u8>>::deserialize(deserializer)?);
        let note_buf = Box::from(bytes.as_slice());
        Ok(SecretBuf(note_buf))
    }
}
