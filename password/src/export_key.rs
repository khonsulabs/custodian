//! See [`ExportKey`].

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// Secret key derived from the users password on the client. The server has no
/// access to it! Can be used to encrypt data and store it safely at the server.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ExportKey(#[serde(with = "BigArray")] pub(crate) [u8; 64]);
