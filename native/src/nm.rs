//! Chrome native-messaging wire protocol.
//!
//! Each message is a 4-byte length prefix in **native byte order** followed by
//! that many bytes of UTF-8 JSON. Verified against Chrome's native-messaging
//! docs. Host→Chrome messages are capped at 1 MB by Chrome; we enforce that on
//! write so we fail loudly rather than have Chrome silently drop the message.

use std::io::{self, Read, Write};

/// Chrome's cap on a single host→browser message.
const MAX_OUTGOING: usize = 1024 * 1024;
/// Defensive cap on incoming length so a corrupt prefix can't make us eagerly
/// allocate a huge buffer. Chrome allows up to 4 GB inbound, but hecate requests
/// are tiny JSON objects — 4 MB is already absurdly generous and bounds a bad
/// prefix to a harmless allocation.
const MAX_INCOMING: usize = 4 * 1024 * 1024;

/// Read one framed message from `r`. Returns `Ok(None)` on a clean EOF at a
/// message boundary (the browser closed the port), `Err` on a partial/corrupt
/// frame.
pub fn read_message(r: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut len_buf = [0u8; 4];
    if !read_exact_or_eof(r, &mut len_buf)? {
        return Ok(None); // clean EOF before any bytes — port closed
    }
    let len = u32::from_ne_bytes(len_buf) as usize;
    if len > MAX_INCOMING {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("incoming message length {len} exceeds cap {MAX_INCOMING}"),
        ));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(Some(body))
}

/// Write one framed message to `w`.
pub fn write_message(w: &mut impl Write, body: &[u8]) -> io::Result<()> {
    if body.len() > MAX_OUTGOING {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "outgoing message length {} exceeds Chrome's 1 MB cap",
                body.len()
            ),
        ));
    }
    let len = body.len() as u32;
    w.write_all(&len.to_ne_bytes())?;
    w.write_all(body)?;
    w.flush()
}

/// Like `read_exact`, but distinguishes "clean EOF before any byte" (`Ok(false)`)
/// from "EOF partway through" (an `UnexpectedEof` error).
fn read_exact_or_eof(r: &mut impl Read, buf: &mut [u8]) -> io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => {
                if filled == 0 {
                    return Ok(false);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "EOF in the middle of a length prefix",
                ));
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn write_then_read_roundtrips() {
        let mut buf = Vec::new();
        write_message(&mut buf, br#"{"op":"list"}"#).unwrap();
        let mut cur = Cursor::new(buf);
        let got = read_message(&mut cur).unwrap().unwrap();
        assert_eq!(got, br#"{"op":"list"}"#);
    }

    #[test]
    fn clean_eof_returns_none() {
        let mut cur = Cursor::new(Vec::new());
        assert!(read_message(&mut cur).unwrap().is_none());
    }

    #[test]
    fn two_messages_in_sequence() {
        let mut buf = Vec::new();
        write_message(&mut buf, b"first").unwrap();
        write_message(&mut buf, b"second").unwrap();
        let mut cur = Cursor::new(buf);
        assert_eq!(read_message(&mut cur).unwrap().unwrap(), b"first");
        assert_eq!(read_message(&mut cur).unwrap().unwrap(), b"second");
        assert!(read_message(&mut cur).unwrap().is_none());
    }

    #[test]
    fn partial_prefix_is_error() {
        let mut cur = Cursor::new(vec![0x01, 0x00]); // 2 bytes, not 4
        assert!(read_message(&mut cur).is_err());
    }
}
