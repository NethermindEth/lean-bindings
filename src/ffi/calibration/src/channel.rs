//! Authenticated framing between the coordinator and workers, under a per-run secret.
//!
//! The server opens with a fresh 32-byte challenge. The client answers `keccak256(key ‖ "auth" ‖ challenge)`, in a
//! frame of at most [`MAX_CONTROL_FRAME`] bytes; until it does, nothing larger is read. Every later frame carries
//! `keccak256(key ‖ challenge ‖ direction ‖ sequence ‖ payload)`, so frames cannot be forged, reordered or replayed
//! into another connection. Keccak-256 is not length-extendable, so the keyed prefix is a MAC.
//!
//! The key is 32 bytes, hex in `CALIB_TOKEN` or in the file `CALIB_TOKEN_FILE`; it is never printed.

use crate::wire::{MAX_CONTROL_FRAME, MAX_DATA_FRAME, read_frame, write_frame};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

pub type Key = [u8; 32];

const AUTH: &[u8] = b"auth";
const TO_SERVER: u8 = 0;
const TO_CLIENT: u8 = 1;

fn denied(what: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, what.to_string())
}

fn parse_hex(s: &str) -> Option<Key> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut out = [0; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// The run's key from the environment.
pub fn key_from_env() -> io::Result<Key> {
    let text = match (
        std::env::var("CALIB_TOKEN"),
        std::env::var("CALIB_TOKEN_FILE"),
    ) {
        (Ok(t), _) => t,
        (_, Ok(path)) => std::fs::read_to_string(path)?,
        _ => {
            return Err(denied(
                "set CALIB_TOKEN or CALIB_TOKEN_FILE to the run's 32-byte hex key",
            ));
        }
    };
    parse_hex(&text).ok_or_else(|| denied("the run key is not 64 hex digits"))
}

fn mac(key: &Key, parts: &[&[u8]]) -> [u8; 32] {
    let mut pre = key.to_vec();
    for p in parts {
        pre.extend_from_slice(p);
    }
    primitives::hash::hash(&pre)
}

fn equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

fn challenge() -> io::Result<[u8; 32]> {
    let mut c = [0; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut c)?;
    Ok(c)
}

pub struct Channel<S> {
    stream: S,
    key: Key,
    challenge: [u8; 32],
    send_dir: u8,
    sent: u64,
    received: u64,
}

impl Channel<TcpStream> {
    /// The accepting side: issues a challenge and requires the client's answer, exactly one 32-byte frame, within
    /// `limit` in total; a slower or longer answer is refused.
    pub fn server(mut stream: TcpStream, key: Key, limit: Duration) -> io::Result<Self> {
        let deadline = Instant::now() + limit;
        let challenge = challenge()?;
        stream.set_write_timeout(Some(limit))?;
        write_frame(&mut stream, &challenge)?;
        let mut answer = [0u8; 4 + 32];
        let mut got = 0;
        while got < answer.len() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "handshake deadline",
                ));
            }
            stream.set_read_timeout(Some(left))?;
            match stream.read(&mut answer[got..]) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(n) => got += n,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "handshake deadline",
                    ));
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
            if got >= 4 && u32::from_le_bytes(answer[..4].try_into().unwrap()) != 32 {
                return Err(denied("the handshake answer is not 32 bytes"));
            }
        }
        if !equal(&answer[4..], &mac(&key, &[AUTH, &challenge])) {
            return Err(denied("the peer does not hold the run key"));
        }
        stream.set_read_timeout(None)?;
        stream.set_write_timeout(None)?;
        Ok(Self {
            stream,
            key,
            challenge,
            send_dir: TO_CLIENT,
            sent: 0,
            received: 0,
        })
    }
}

impl<S: Read + Write> Channel<S> {
    /// The connecting side: answers the server's challenge.
    pub fn client(mut stream: S, key: Key) -> io::Result<Self> {
        let c = read_frame(&mut stream, MAX_CONTROL_FRAME)?;
        let challenge: [u8; 32] = c.try_into().map_err(|_| denied("malformed challenge"))?;
        write_frame(&mut stream, &mac(&key, &[AUTH, &challenge]))?;
        Ok(Self {
            stream,
            key,
            challenge,
            send_dir: TO_SERVER,
            sent: 0,
            received: 0,
        })
    }

    pub fn send(&mut self, payload: &[u8]) -> io::Result<()> {
        let tag = mac(
            &self.key,
            &[
                &self.challenge,
                &[self.send_dir],
                &self.sent.to_le_bytes(),
                payload,
            ],
        );
        self.sent += 1;
        let mut frame = Vec::with_capacity(32 + payload.len());
        frame.extend_from_slice(&tag);
        frame.extend_from_slice(payload);
        write_frame(&mut self.stream, &frame)
    }

    pub fn recv(&mut self) -> io::Result<Vec<u8>> {
        let mut frame = read_frame(&mut self.stream, MAX_DATA_FRAME + 32)?;
        if frame.len() < 32 {
            return Err(denied("unauthenticated frame"));
        }
        let payload = frame.split_off(32);
        let dir = 1 - self.send_dir;
        if !equal(
            &frame,
            &mac(
                &self.key,
                &[
                    &self.challenge,
                    &[dir],
                    &self.received.to_le_bytes(),
                    &payload,
                ],
            ),
        ) {
            return Err(denied("unauthenticated frame"));
        }
        self.received += 1;
        Ok(payload)
    }

    pub fn get_ref(&self) -> &S {
        &self.stream
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    const LIMIT: Duration = Duration::from_secs(5);

    fn pair(
        server_key: Key,
        client_key: Key,
    ) -> (
        io::Result<Channel<TcpStream>>,
        io::Result<Channel<TcpStream>>,
    ) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let t =
            std::thread::spawn(move || Channel::server(l.accept().unwrap().0, server_key, LIMIT));
        let c = Channel::client(TcpStream::connect(addr).unwrap(), client_key);
        (t.join().unwrap(), c)
    }

    #[test]
    fn frames_round_trip_under_the_shared_key() {
        let (s, c) = pair([1; 32], [1; 32]);
        let (mut s, mut c) = (s.unwrap(), c.unwrap());
        c.send(b"hello").unwrap();
        c.send(b"again").unwrap();
        assert_eq!(s.recv().unwrap(), b"hello");
        assert_eq!(s.recv().unwrap(), b"again");
        s.send(b"reply").unwrap();
        assert_eq!(c.recv().unwrap(), b"reply");
    }

    #[test]
    fn a_wrong_key_is_refused_at_the_handshake() {
        let (s, _c) = pair([1; 32], [2; 32]);
        assert_eq!(s.err().unwrap().kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn unauthenticated_or_replayed_frames_are_refused() {
        let (s, c) = pair([3; 32], [3; 32]);
        let (mut s, c) = (s.unwrap(), c.unwrap());
        let mut raw = c.get_ref().try_clone().unwrap();
        // A frame without a valid tag: a bare RESET byte, then a tag forged without the key.
        write_frame(&mut raw, &[7]).unwrap();
        assert_eq!(
            s.recv().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        let mut forged = mac(
            &[0; 32],
            &[&[0u8; 32], &[TO_SERVER], &0u64.to_le_bytes(), &[7]],
        )
        .to_vec();
        forged.push(7);
        write_frame(&mut raw, &forged).unwrap();
        assert_eq!(
            s.recv().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn a_large_frame_before_authenticating_is_not_read() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            Channel::server(l.accept().unwrap().0, [5; 32], LIMIT)
                .err()
                .unwrap()
        });
        let mut s = TcpStream::connect(addr).unwrap();
        read_frame(&mut s, MAX_CONTROL_FRAME).unwrap();
        s.write_all(&(MAX_DATA_FRAME as u32).to_le_bytes()).unwrap();
        assert_eq!(t.join().unwrap().kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn a_slow_drip_peer_times_out_within_the_deadline() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let limit = Duration::from_millis(600);
        let t = std::thread::spawn(move || {
            let s = l.accept().unwrap().0;
            let start = Instant::now();
            (
                Channel::server(s, [6; 32], limit).err().unwrap(),
                start.elapsed(),
            )
        });
        let mut s = TcpStream::connect(addr).unwrap();
        read_frame(&mut s, MAX_CONTROL_FRAME).unwrap();
        // A valid length, then one byte every 100 ms: each read succeeds, only the total deadline stops it.
        s.write_all(&32u32.to_le_bytes()).unwrap();
        for _ in 0..30 {
            if s.write_all(&[0]).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let (err, took) = t.join().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(took < Duration::from_millis(1500), "took {took:?}");
    }

    #[test]
    fn keys_parse_from_hex_only() {
        assert_eq!(parse_hex(&"ab".repeat(32)), Some([0xab; 32]));
        assert_eq!(parse_hex("ab"), None);
        assert_eq!(parse_hex(&"zz".repeat(32)), None);
    }
}
