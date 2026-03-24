use std::io::{Read, Write};

use crate::{Error, Result};

pub const FRAME_KIND_CMD: u8 = 1;
pub const FRAME_KIND_CMD_JSON: u8 = 2;
pub const FRAME_KIND_HELLO: u8 = 0x80;
pub const FRAME_KIND_LOG: u8 = 0x81;
pub const FRAME_KIND_COMPLETE: u8 = 0x82;
pub const FRAME_KIND_EVAL_OK: u8 = 0x83;
pub const FRAME_KIND_EVAL_ERR: u8 = 0x84;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    Command,
    CommandJson,
    Hello,
    Log,
    Complete,
    EvalOk,
    EvalErr,
}

impl FrameKind {
    pub fn as_u8(self) -> u8 {
        match self {
            FrameKind::Command => FRAME_KIND_CMD,
            FrameKind::CommandJson => FRAME_KIND_CMD_JSON,
            FrameKind::Hello => FRAME_KIND_HELLO,
            FrameKind::Log => FRAME_KIND_LOG,
            FrameKind::Complete => FRAME_KIND_COMPLETE,
            FrameKind::EvalOk => FRAME_KIND_EVAL_OK,
            FrameKind::EvalErr => FRAME_KIND_EVAL_ERR,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Hello {
    pub platform: String,
    pub arch: String,
    pub runtime: String,
    pub transport: String,
}

impl Hello {
    pub fn ios_default() -> Self {
        Self {
            platform: "ios".into(),
            arch: std::env::consts::ARCH.into(),
            runtime: "quickjs-runtime".into(),
            transport: "unix-fd".into(),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        format!(
            "platform={};arch={};runtime={};transport={}",
            self.platform, self.arch, self.runtime, self.transport
        )
        .into_bytes()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let text = String::from_utf8(bytes.to_vec())
            .map_err(|_| Error::Protocol("hello payload is not valid utf-8".into()))?;
        let mut hello = Hello {
            platform: String::new(),
            arch: String::new(),
            runtime: String::new(),
            transport: String::new(),
        };

        for item in text.split(';') {
            let Some((key, value)) = item.split_once('=') else {
                continue;
            };
            match key {
                "platform" => hello.platform = value.into(),
                "arch" => hello.arch = value.into(),
                "runtime" => hello.runtime = value.into(),
                "transport" => hello.transport = value.into(),
                _ => {}
            }
        }

        if hello.platform.is_empty() || hello.runtime.is_empty() {
            return Err(Error::Protocol("hello payload is incomplete".into()));
        }
        Ok(hello)
    }
}

#[derive(Debug, Clone)]
pub enum AgentEvent {
    Hello(Hello),
    Log(String),
    Complete(Vec<String>),
    EvalOk(String),
    EvalErr(String),
}

pub fn write_frame(writer: &mut dyn Write, kind: u8, payload: &[u8]) -> Result<()> {
    writer.write_all(&[kind])?;
    writer.write_all(&(payload.len() as u32).to_le_bytes())?;
    writer.write_all(payload)?;
    Ok(())
}

pub fn read_frame(reader: &mut dyn Read) -> Result<(u8, Vec<u8>)> {
    let mut kind = [0u8; 1];
    reader.read_exact(&mut kind)?;
    let mut len = [0u8; 4];
    reader.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    Ok((kind[0], payload))
}

pub fn decode_event(kind: u8, payload: Vec<u8>) -> Result<AgentEvent> {
    match kind {
        FRAME_KIND_HELLO => Ok(AgentEvent::Hello(Hello::decode(&payload)?)),
        FRAME_KIND_LOG => Ok(AgentEvent::Log(
            String::from_utf8(payload).map_err(|_| Error::Protocol("log payload is not utf-8".into()))?,
        )),
        FRAME_KIND_COMPLETE => {
            let text =
                String::from_utf8(payload).map_err(|_| Error::Protocol("completion payload is not utf-8".into()))?;
            let items = if text.is_empty() {
                Vec::new()
            } else {
                text.split('\t').map(|item| item.to_string()).collect()
            };
            Ok(AgentEvent::Complete(items))
        }
        FRAME_KIND_EVAL_OK => Ok(AgentEvent::EvalOk(
            String::from_utf8(payload).map_err(|_| Error::Protocol("eval payload is not utf-8".into()))?,
        )),
        FRAME_KIND_EVAL_ERR => {
            Ok(AgentEvent::EvalErr(String::from_utf8(payload).map_err(|_| {
                Error::Protocol("eval error payload is not utf-8".into())
            })?))
        }
        _ => Err(Error::Protocol(format!("unknown frame kind: {kind}"))),
    }
}
