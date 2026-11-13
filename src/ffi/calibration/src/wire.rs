//! Length-prefixed binary encoding for corpus files and the coordinator/worker protocol.
//!
//! Integers are little-endian; byte strings are a u32 length then the bytes. A frame on a socket is a u32 length then
//! that many bytes, read against a caller-chosen bound and buffered only as the bytes arrive.

use crate::api::{Leaf, RawSig};
use rec_aggregation::EthereumClaims;
use signatures::lean_sphincs::{
    LeanSphincsPublicKey, LeanSphincsSignature, PUB_KEY_SIZE, SIG_SIZE,
};
use std::io::{self, Read, Write};

/// The largest frame accepted before a peer has authenticated (handshake and control messages).
pub const MAX_CONTROL_FRAME: usize = 64 << 10;

/// The largest authenticated frame: a task of `MAX_INNER_PROOFS_PER_STEP` leaves at the library's 8 MiB witness bound,
/// with its signatures, or one proof and its claims, stays below it.
pub const MAX_DATA_FRAME: usize = 256 << 20;

/// Bytes read at a time, so a claimed length never allocates more than has arrived.
const CHUNK: usize = 1 << 20;

#[derive(Default)]
pub struct Writer {
    pub buf: Vec<u8>,
}

impl Writer {
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn f64(&mut self, v: f64) -> &mut Self {
        self.u64(v.to_bits())
    }
    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.u32(u32::try_from(v.len()).expect("a field under 4 GiB"));
        self.buf.extend_from_slice(v);
        self
    }
    pub fn fixed(&mut self, v: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(v);
        self
    }
    pub fn str(&mut self, v: &str) -> &mut Self {
        self.bytes(v.as_bytes())
    }
}

pub struct Reader<'a> {
    pub bytes: &'a [u8],
}

fn short() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "truncated message")
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
    fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        if self.bytes.len() < n {
            return Err(short());
        }
        let (head, tail) = self.bytes.split_at(n);
        self.bytes = tail;
        Ok(head)
    }
    pub fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn f64(&mut self) -> io::Result<f64> {
        Ok(f64::from_bits(self.u64()?))
    }
    pub fn bytes(&mut self) -> io::Result<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    pub fn fixed<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    pub fn str(&mut self) -> io::Result<String> {
        String::from_utf8(self.bytes()?.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "utf-8"))
    }
    /// A count of items each at least `min` bytes, checked against what is left before allocating.
    pub fn count(&mut self, min: usize) -> io::Result<usize> {
        let n = self.u32()? as usize;
        if n.saturating_mul(min.max(1)) > self.bytes.len() {
            return Err(short());
        }
        Ok(n)
    }
    pub fn end(&self) -> io::Result<()> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::InvalidData, "trailing bytes"))
        }
    }
}

pub fn write_frame(w: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    w.write_all(
        &u32::try_from(payload.len())
            .expect("a frame under 4 GiB")
            .to_le_bytes(),
    )?;
    w.write_all(payload)?;
    w.flush()
}

/// Reads one frame of at most `max` bytes. A larger claimed length fails before any payload is read, and the buffer
/// grows a chunk at a time, so a peer that claims more than it sends costs at most one chunk.
pub fn read_frame(r: &mut impl Read, max: usize) -> io::Result<Vec<u8>> {
    let mut len = [0; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    if len > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut buf = Vec::with_capacity(len.min(CHUNK));
    while buf.len() < len {
        let start = buf.len();
        let step = (len - start).min(CHUNK);
        buf.resize(start + step, 0);
        r.read_exact(&mut buf[start..])?;
    }
    Ok(buf)
}

pub fn put_leaf(w: &mut Writer, leaf: &Leaf) {
    w.u32(leaf.claims.len() as u32);
    for c in &leaf.claims {
        w.fixed(c);
    }
    w.fixed(&leaf.vk).bytes(&leaf.witness);
}

pub fn get_leaf(r: &mut Reader) -> io::Result<Leaf> {
    let n = r.count(32)?;
    let claims = (0..n).map(|_| r.fixed::<32>()).collect::<io::Result<_>>()?;
    Ok(Leaf {
        claims,
        vk: r.fixed()?,
        witness: r.bytes()?.to_vec(),
    })
}

pub fn put_sigs(w: &mut Writer, sigs: &[RawSig]) {
    w.u32(sigs.len() as u32);
    for (pk, msg, sig) in sigs {
        w.fixed(&pk.to_bytes()).fixed(msg).fixed(&sig.to_bytes());
    }
}

pub fn get_sigs(r: &mut Reader) -> io::Result<Vec<RawSig>> {
    let n = r.count(PUB_KEY_SIZE + 32 + SIG_SIZE)?;
    (0..n)
        .map(|_| {
            let pk = LeanSphincsPublicKey::from_bytes(&r.fixed::<PUB_KEY_SIZE>()?);
            let msg = r.fixed::<32>()?;
            let sig = LeanSphincsSignature::from_bytes(&r.fixed::<SIG_SIZE>()?);
            Ok((pk, msg, sig))
        })
        .collect()
}

pub fn put_claims(w: &mut Writer, c: &EthereumClaims) {
    w.u32(c.generic.len() as u32);
    for (d, k) in &c.generic {
        w.fixed(d).fixed(k);
    }
    w.u32(c.lean_sphincs.len() as u32);
    for (m, pk) in &c.lean_sphincs {
        w.fixed(m).fixed(&pk.to_bytes());
    }
    match &c.da_commitment {
        Some(d) => w.u8(1).fixed(d),
        None => w.u8(0),
    };
}

pub fn get_claims(r: &mut Reader) -> io::Result<EthereumClaims> {
    let n = r.count(64)?;
    let generic = (0..n)
        .map(|_| Ok((r.fixed::<32>()?, r.fixed::<32>()?)))
        .collect::<io::Result<_>>()?;
    let n = r.count(32 + PUB_KEY_SIZE)?;
    let lean_sphincs = (0..n)
        .map(|_| {
            Ok((
                r.fixed::<32>()?,
                LeanSphincsPublicKey::from_bytes(&r.fixed::<PUB_KEY_SIZE>()?),
            ))
        })
        .collect::<io::Result<_>>()?;
    let da_commitment = match r.u8()? {
        0 => None,
        1 => Some(r.fixed()?),
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "da flag")),
    };
    Ok(EthereumClaims {
        generic,
        lean_sphincs,
        da_commitment,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_and_fields_round_trip() {
        let leaf = Leaf {
            claims: vec![[1; 32], [2; 32]],
            vk: [3; 32],
            witness: vec![9; 1000],
        };
        let claims = EthereumClaims {
            generic: vec![([4; 32], [5; 32])],
            da_commitment: Some([6; 32]),
            ..Default::default()
        };
        let mut w = Writer::default();
        w.u64(7).f64(1.5).str("x");
        put_leaf(&mut w, &leaf);
        put_claims(&mut w, &claims);
        let mut socket = Vec::new();
        write_frame(&mut socket, &w.buf).unwrap();
        assert!(read_frame(&mut socket.as_slice(), w.buf.len() - 1).is_err());
        let frame = read_frame(&mut socket.as_slice(), MAX_DATA_FRAME).unwrap();
        let mut r = Reader::new(&frame);
        assert_eq!(
            (r.u64().unwrap(), r.f64().unwrap(), r.str().unwrap()),
            (7, 1.5, "x".to_string())
        );
        assert_eq!(get_leaf(&mut r).unwrap(), leaf);
        assert_eq!(get_claims(&mut r).unwrap(), claims);
        r.end().unwrap();
    }

    #[test]
    fn counts_are_checked_before_allocating() {
        let mut w = Writer::default();
        w.u32(u32::MAX);
        assert!(get_leaf(&mut Reader::new(&w.buf)).is_err());
        // A length over the bound fails at once; one under it that the peer never sends fails after one chunk.
        assert!(read_frame(&mut [0xff, 0xff, 0xff, 0xff].as_slice(), MAX_DATA_FRAME).is_err());
        let mut claimed = ((MAX_DATA_FRAME - 1) as u32).to_le_bytes().to_vec();
        claimed.extend([7; 10]);
        let err = read_frame(&mut claimed.as_slice(), MAX_DATA_FRAME).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        let control = (MAX_CONTROL_FRAME as u32 + 1).to_le_bytes();
        assert!(read_frame(&mut control.as_slice(), MAX_CONTROL_FRAME).is_err());
    }
}
