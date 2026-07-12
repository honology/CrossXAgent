use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::RelayError;

/// Largest permitted JSON envelope, in bytes.
pub const MAX_FRAME_SIZE: usize = 1024 * 1024;

#[derive(Deserialize)]
struct IncomingEnvelope {
    t: String,
    d: serde_json::Value,
}

#[derive(Serialize)]
struct OutgoingEnvelope<'a, T: ?Sized> {
    t: &'a str,
    d: &'a T,
}

/// Writes one length-prefixed JSON control frame.
pub async fn write_frame<W, T>(
    writer: &mut W,
    message_type: &str,
    payload: &T,
) -> Result<(), RelayError>
where
    W: AsyncWrite + Unpin,
    T: Serialize + ?Sized,
{
    let envelope = serde_json::to_vec(&OutgoingEnvelope {
        t: message_type,
        d: payload,
    })
    .map_err(|error| RelayError::Protocol(error.to_string()))?;
    validate_length(envelope.len())?;
    let length = u32::try_from(envelope.len())
        .map_err(|_| RelayError::Protocol("frame length exceeds uint32".to_owned()))?;
    writer.write_all(&length.to_be_bytes()).await?;
    writer.write_all(&envelope).await?;
    writer.flush().await?;
    Ok(())
}

/// Reads exactly one frame and decodes its payload as the requested type.
pub async fn read_frame<R, T>(reader: &mut R, expected_type: &str) -> Result<T, RelayError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let length = reader.read_u32().await? as usize;
    validate_length(length)?;
    let mut bytes = vec![0_u8; length];
    reader.read_exact(&mut bytes).await?;
    let envelope: IncomingEnvelope = serde_json::from_slice(&bytes)
        .map_err(|error| RelayError::Protocol(format!("invalid frame JSON: {error}")))?;
    if envelope.t != expected_type {
        return Err(RelayError::Protocol(format!(
            "expected {expected_type} frame, received {}",
            envelope.t
        )));
    }
    serde_json::from_value(envelope.d)
        .map_err(|error| RelayError::Protocol(format!("invalid {expected_type} payload: {error}")))
}

fn validate_length(length: usize) -> Result<(), RelayError> {
    if length == 0 || length > MAX_FRAME_SIZE {
        return Err(RelayError::Protocol(format!(
            "invalid frame length {length}"
        )));
    }
    Ok(())
}
