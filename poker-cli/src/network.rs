use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use anyhow::{Context, Result};

#[derive(Serialize, Deserialize, Debug)]
pub enum Message {
    Hello {
        pk: Vec<u8>,
        proof: Vec<u8>,
    },
    ShuffledDeck {
        deck: Vec<u8>,
        proof: Vec<u8>,
    },
    RequestToken {
        card_idx: usize,
    },
    Token {
        token: Vec<u8>,
        proof: Vec<u8>,
    },
    Action {
        action: GameAction,
    },
    Text(String),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum GameAction {
    Bet(u32),
    Call,
    Fold,
    Check,
    Ack, // Acknowledge end of hand or state
}

pub fn send_message(stream: &mut TcpStream, msg: &Message) -> Result<()> {
    let bytes = bincode::serialize(msg).context("Failed to serialize message")?;
    let len = bytes.len() as u32;
    stream.write_all(&len.to_be_bytes()).context("Failed to write length prefix")?;
    stream.write_all(&bytes).context("Failed to write message body")?;
    stream.flush().context("Failed to flush stream")?;
    Ok(())
}

pub fn recv_message(stream: &mut TcpStream) -> Result<Message> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).context("Failed to read length prefix")?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).context("Failed to read message body")?;
    
    let msg = bincode::deserialize(&buf).context("Failed to deserialize message")?;
    Ok(msg)
}
