//! Minimal blocking D-Bus client: wire codec and one connection.
//!
//! Just enough for the suspend guard.

use std::{
    collections::VecDeque,
    ffi::OsStr,
    io::{Error, ErrorKind, Result, Write},
    os::{
        fd::OwnedFd,
        linux::net::SocketAddrExt,
        unix::{
            ffi::OsStrExt,
            net::{SocketAddr, UnixStream},
        },
    },
    time::{Duration, Instant},
};

pub const METHOD_CALL: u8 = 1;
pub const METHOD_RETURN: u8 = 2;
pub const ERROR: u8 = 3;
pub const SIGNAL: u8 = 4;

pub const BUS: &str = "org.freedesktop.DBus";
pub const BUS_PATH: &str = "/org/freedesktop/DBus";

// A call must never start a service: what is not running cannot help.
const NO_AUTO_START: u8 = 2;
const MAX_MESSAGE: usize = 1 << 20;
const MAX_PENDING: usize = 64;
const WRITE_TIMEOUT: Duration = Duration::from_secs(2);

/// Marshals values, little endian.
#[derive(Default)]
pub struct Writer {
    pub buf: Vec<u8>,
}

impl Writer {
    pub fn align(&mut self, to: usize) {
        while !self.buf.len().is_multiple_of(to) {
            self.buf.push(0);
        }
    }

    pub fn byte(&mut self, value: u8) {
        self.buf.push(value);
    }

    pub fn u32(&mut self, value: u32) {
        self.align(4);
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    /// Types `s` and `o`.
    pub fn string(&mut self, value: &str) {
        self.u32(value.len() as u32);
        self.buf.extend_from_slice(value.as_bytes());
        self.buf.push(0);
    }

    /// Type `g`.
    pub fn signature(&mut self, value: &str) {
        self.buf.push(value.len() as u8);
        self.buf.extend_from_slice(value.as_bytes());
        self.buf.push(0);
    }

    /// An array whose elements align to `element_align`.
    pub fn array(&mut self, element_align: usize, fill: impl FnOnce(&mut Self)) {
        self.u32(0);
        let length_at = self.buf.len() - 4;
        self.align(element_align);
        let start = self.buf.len();
        fill(self);
        let length = (self.buf.len() - start) as u32;
        if let Some(slot) = self.buf.get_mut(length_at..length_at + 4) {
            slot.copy_from_slice(&length.to_le_bytes());
        }
    }
}

/// Unmarshals values in the sender's byte order.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    big_endian: bool,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8], big_endian: bool) -> Self {
        Self {
            buf,
            pos: 0,
            big_endian,
        }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(len)?;
        let bytes = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(bytes)
    }

    pub fn align(&mut self, to: usize) -> Option<()> {
        self.take((to - self.pos % to) % to).map(|_| ())
    }

    pub fn byte(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }

    pub fn u32(&mut self) -> Option<u32> {
        self.align(4)?;
        let bytes = self.take(4)?.try_into().ok()?;
        Some(if self.big_endian {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        })
    }

    pub fn u64(&mut self) -> Option<u64> {
        self.align(8)?;
        let bytes = self.take(8)?.try_into().ok()?;
        Some(if self.big_endian {
            u64::from_be_bytes(bytes)
        } else {
            u64::from_le_bytes(bytes)
        })
    }

    /// Types `s` and `o`.
    pub fn string(&mut self) -> Option<&'a str> {
        let len = self.u32()? as usize;
        let bytes = self.take(len)?;
        self.take(1)?;
        std::str::from_utf8(bytes).ok()
    }

    /// Type `g`.
    pub fn signature(&mut self) -> Option<&'a str> {
        let len = usize::from(self.byte()?);
        let bytes = self.take(len)?;
        self.take(1)?;
        std::str::from_utf8(bytes).ok()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Message {
    pub kind: u8,
    pub serial: u32,
    pub reply_serial: u32,
    pub path: String,
    pub interface: String,
    pub member: String,
    pub error_name: String,
    pub destination: String,
    pub sender: String,
    pub signature: String,
    pub unix_fds: u32,
    pub body: Vec<u8>,
    /// Byte order of a received body.
    pub big_endian: bool,
}

impl Message {
    pub fn call(destination: &str, path: &str, interface: &str, member: &str) -> Self {
        Self {
            kind: METHOD_CALL,
            destination: destination.into(),
            path: path.into(),
            interface: interface.into(),
            member: member.into(),
            ..Self::default()
        }
    }

    pub fn with_body(mut self, signature: &str, body: Writer) -> Self {
        self.signature = signature.into();
        self.body = body.buf;
        self
    }

    pub fn reader(&self) -> Reader<'_> {
        Reader::new(&self.body, self.big_endian)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Writer::default();
        out.byte(b'l');
        out.byte(self.kind);
        out.byte(if self.kind == METHOD_CALL {
            NO_AUTO_START
        } else {
            0
        });
        out.byte(1);
        out.u32(self.body.len() as u32);
        out.u32(self.serial);
        out.array(8, |fields| {
            for (code, kind, value) in [
                (1, "o", &self.path),
                (2, "s", &self.interface),
                (3, "s", &self.member),
                (4, "s", &self.error_name),
                (6, "s", &self.destination),
                (7, "s", &self.sender),
            ] {
                if !value.is_empty() {
                    fields.align(8);
                    fields.byte(code);
                    fields.signature(kind);
                    fields.string(value);
                }
            }
            for (code, value) in [(5, self.reply_serial), (9, self.unix_fds)] {
                if value != 0 {
                    fields.align(8);
                    fields.byte(code);
                    fields.signature("u");
                    fields.u32(value);
                }
            }
            if !self.signature.is_empty() {
                fields.align(8);
                fields.byte(8);
                fields.signature("g");
                fields.signature(&self.signature);
            }
        });
        out.align(8);
        out.buf.extend_from_slice(&self.body);
        out.buf
    }

    /// Parses one complete message. `None` for anything this client does not
    /// understand; the caller skips it by its length.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let big_endian = match bytes.first()? {
            b'l' => false,
            b'B' => true,
            _ => return None,
        };
        let mut header = Reader::new(bytes, big_endian);
        header.byte()?;
        let kind = header.byte()?;
        header.byte()?;
        if header.byte()? != 1 {
            return None;
        }
        let body_len = header.u32()? as usize;
        let serial = header.u32()?;
        let fields_len = header.u32()? as usize;
        let fields_end = header.position().checked_add(fields_len)?;
        let mut message = Self {
            kind,
            serial,
            big_endian,
            ..Self::default()
        };
        while header.position() < fields_end {
            header.align(8)?;
            let code = header.byte()?;
            match (code, header.signature()?) {
                (1, "o") => message.path = header.string()?.into(),
                (2, "s") => message.interface = header.string()?.into(),
                (3, "s") => message.member = header.string()?.into(),
                (4, "s") => message.error_name = header.string()?.into(),
                (5, "u") => message.reply_serial = header.u32()?,
                (6, "s") => message.destination = header.string()?.into(),
                (7, "s") => message.sender = header.string()?.into(),
                (8, "g") => message.signature = header.signature()?.into(),
                (9, "u") => message.unix_fds = header.u32()?,
                _ => return None,
            }
        }
        if header.position() != fields_end {
            return None;
        }
        header.align(8)?;
        message.body = header.take(body_len)?.to_vec();
        Some(message)
    }
}

/// Length of the message that starts `bytes`, once its fixed header is there.
pub fn message_len(bytes: &[u8]) -> Result<Option<usize>> {
    let Some(fixed) = bytes.get(..16) else {
        return Ok(None);
    };
    let invalid = || Error::new(ErrorKind::InvalidData, "invalid D-Bus message header");
    let big_endian = match fixed.first() {
        Some(b'l') => false,
        Some(b'B') => true,
        _ => return Err(invalid()),
    };
    let mut header = Reader::new(fixed, big_endian);
    header.take(4);
    let body = header.u32().ok_or_else(invalid)? as usize;
    header.u32();
    let fields = header.u32().ok_or_else(invalid)? as usize;
    let total = fields
        .checked_next_multiple_of(8)
        .and_then(|fields| fields.checked_add(16))
        .and_then(|header| header.checked_add(body))
        .filter(|total| *total <= MAX_MESSAGE)
        .ok_or_else(invalid)?;
    Ok(Some(total))
}

fn unescape(value: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(value.len());
    let mut bytes = value.bytes();
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let hex = [bytes.next()?, bytes.next()?];
            out.push(u8::from_str_radix(std::str::from_utf8(&hex).ok()?, 16).ok()?);
        } else {
            out.push(byte);
        }
    }
    Some(out)
}

/// The first `unix:` entry of a bus address that names a socket.
pub fn socket_address(address: &str) -> Option<SocketAddr> {
    for entry in address.split(';') {
        let Some(parameters) = entry.strip_prefix("unix:") else {
            continue;
        };
        for parameter in parameters.split(',') {
            let Some((key, value)) = parameter.split_once('=') else {
                continue;
            };
            let value = unescape(value)?;
            match key {
                "path" => return SocketAddr::from_pathname(OsStr::from_bytes(&value)).ok(),
                "abstract" => return SocketAddr::from_abstract_name(&value).ok(),
                _ => {}
            }
        }
    }
    None
}

/// Reads from the socket. The runtime's version also collects passed descriptors.
pub type Receive = fn(&UnixStream, &mut [u8], &mut VecDeque<OwnedFd>) -> Result<usize>;

pub struct Connection {
    stream: UnixStream,
    receive: Receive,
    buffer: Vec<u8>,
    serial: u32,
    /// Descriptors received so far, oldest first.
    pub fds: VecDeque<OwnedFd>,
    /// Signals and calls that arrived while a reply was awaited.
    pub pending: VecDeque<Message>,
}

impl Connection {
    /// Connects, authenticates as `uid` and says `Hello`.
    pub fn open(address: &str, uid: u32, receive: Receive, deadline: Instant) -> Result<Self> {
        let address = socket_address(address)
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "unsupported bus address"))?;
        let stream = UnixStream::connect_addr(&address)?;
        stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
        let mut connection = Self {
            stream,
            receive,
            buffer: Vec::new(),
            serial: 0,
            fds: VecDeque::new(),
            pending: VecDeque::new(),
        };
        let uid: String = uid
            .to_string()
            .bytes()
            .map(|digit| format!("{digit:02x}"))
            .collect();
        connection.command(&format!("\0AUTH EXTERNAL {uid}\r\n"), "OK ", deadline)?;
        connection.command("NEGOTIATE_UNIX_FD\r\n", "AGREE_UNIX_FD", deadline)?;
        connection.stream.write_all(b"BEGIN\r\n")?;
        let hello = connection.call(Message::call(BUS, BUS_PATH, BUS, "Hello"), deadline)?;
        if hello.kind != METHOD_RETURN {
            return Err(Error::new(ErrorKind::PermissionDenied, "Hello was refused"));
        }
        Ok(connection)
    }

    pub fn stream(&self) -> &UnixStream {
        &self.stream
    }

    fn command(&mut self, line: &str, expected: &str, deadline: Instant) -> Result<()> {
        self.stream.write_all(line.as_bytes())?;
        loop {
            if let Some(end) = self.buffer.windows(2).position(|pair| pair == b"\r\n") {
                let answer: Vec<u8> = self.buffer.drain(..end + 2).collect();
                return if answer.starts_with(expected.as_bytes()) {
                    Ok(())
                } else {
                    Err(Error::new(
                        ErrorKind::PermissionDenied,
                        "bus authentication failed",
                    ))
                };
            }
            self.fill(deadline)?;
        }
    }

    /// Reads more bytes. `TimedOut` once the deadline has passed.
    fn fill(&mut self, deadline: Instant) -> Result<()> {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(ErrorKind::TimedOut.into());
        }
        self.stream.set_read_timeout(Some(left))?;
        let mut chunk = [0u8; 4096];
        match (self.receive)(&self.stream, &mut chunk, &mut self.fds) {
            Ok(0) => Err(ErrorKind::UnexpectedEof.into()),
            Ok(read) => {
                self.buffer
                    .extend_from_slice(chunk.get(..read).unwrap_or_default());
                Ok(())
            }
            Err(error) => match error.kind() {
                ErrorKind::Interrupted => Ok(()),
                ErrorKind::WouldBlock | ErrorKind::TimedOut => Err(ErrorKind::TimedOut.into()),
                _ => Err(error),
            },
        }
    }

    /// The next message, or `None` when the deadline passes first. A deadline
    /// in the past returns only what is already buffered.
    pub fn read(&mut self, deadline: Instant) -> Result<Option<Message>> {
        loop {
            if let Some(length) = message_len(&self.buffer)? {
                if self.buffer.len() >= length {
                    let bytes: Vec<u8> = self.buffer.drain(..length).collect();
                    match Message::decode(&bytes) {
                        Some(message) => return Ok(Some(message)),
                        None => continue,
                    }
                }
            }
            match self.fill(deadline) {
                Ok(()) => {}
                Err(error) if error.kind() == ErrorKind::TimedOut => return Ok(None),
                Err(error) => return Err(error),
            }
        }
    }

    /// Gives the message its serial and returns its wire form.
    pub fn prepare(&mut self, message: &mut Message) -> Vec<u8> {
        self.serial = self.serial.wrapping_add(1).max(1);
        message.serial = self.serial;
        message.encode()
    }

    pub fn send(&mut self, mut message: Message) -> Result<u32> {
        let bytes = self.prepare(&mut message);
        self.stream.write_all(&bytes)?;
        Ok(message.serial)
    }

    /// Sends a call and waits for its reply, which may be an `ERROR`.
    pub fn call(&mut self, message: Message, deadline: Instant) -> Result<Message> {
        let serial = self.send(message)?;
        loop {
            let Some(reply) = self.read(deadline)? else {
                return Err(ErrorKind::TimedOut.into());
            };
            if reply.reply_serial == serial && matches!(reply.kind, METHOD_RETURN | ERROR) {
                return Ok(reply);
            }
            if matches!(reply.kind, METHOD_CALL | SIGNAL) && self.pending.len() < MAX_PENDING {
                self.pending.push_back(reply);
            }
        }
    }
}
