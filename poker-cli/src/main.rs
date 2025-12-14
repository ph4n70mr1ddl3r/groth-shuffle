mod network;

use anyhow::{anyhow, Context, Result};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use clap::{Parser, Subcommand};
use network::{GameAction, Message, recv_message, send_message};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::io::{self, Write};
use std::net::{TcpListener, TcpStream};
use ziffle::{
    AggregatePublicKey, AggregateRevealToken, MaskedCard, MaskedDeck, OwnershipProof, PublicKey,
    RevealToken, RevealTokenProof, SecretKey, Shuffle, ShuffleProof, Verified,
};

type PokerShuffle = Shuffle<52>;
type PokerMaskedDeck = MaskedDeck<52>;
type PokerShuffleProof = ShuffleProof<52>;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Host {
        #[arg(short, long, default_value = "0.0.0.0:8080")]
        bind: String,
    },
    Connect {
        #[arg(short, long, default_value = "127.0.0.1:8080")]
        addr: String,
    },
}

fn to_bytes<T: CanonicalSerialize>(t: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    t.serialize_compressed(&mut bytes).unwrap();
    bytes
}

fn from_bytes<T: CanonicalDeserialize>(bytes: &[u8]) -> Result<T> {
    T::deserialize_compressed(bytes)
        .map_err(|e| anyhow!("Deserialization error: {}", e))
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Host { bind } => {
            println!("Listening on {}...", bind);
            let listener = TcpListener::bind(bind).context("Failed to bind address")?;
            let (stream, addr) = listener.accept().context("Failed to accept connection")?;
            println!("Accepted connection from {}", addr);
            run_game(stream, true)?;
        }
        Commands::Connect { addr } => {
            println!("Connecting to {}...", addr);
            let stream = TcpStream::connect(addr).context("Failed to connect")?;
            println!("Connected!");
            run_game(stream, false)?;
        }
    }

    Ok(())
}

fn run_game(mut stream: TcpStream, is_host: bool) -> Result<()> {
    let mut rng = StdRng::from_entropy();
    let shuffle = PokerShuffle::default();
    let ctx = b"poker-session-v1";

    // 1. Handshake & Key Exchange
    println!("Generating keys...");
    let (sk, pk, ownership_proof) = shuffle.keygen(&mut rng, ctx);
    
    // Send my keys
    send_message(
        &mut stream,
        &Message::Hello {
            pk: to_bytes(&pk),
            proof: to_bytes(&ownership_proof),
        },
    )?;

    // Receive peer keys
    let peer_msg = recv_message(&mut stream)?;
    let (peer_pk, peer_proof) = match peer_msg {
        Message::Hello { pk, proof } => (
            from_bytes::<PublicKey>(&pk)?,
            from_bytes::<OwnershipProof>(&proof)?,
        ),
        _ => return Err(anyhow!("Expected Hello message")),
    };

    println!("Verifying peer keys...");
    let verified_pk = ownership_proof
        .verify(pk, ctx)
        .context("Self key verification failed (should not happen)")?;
    
    let peer_verified_pk = peer_proof
        .verify(peer_pk, ctx)
        .ok_or_else(|| anyhow!("Peer ownership proof verification failed"))?;

    let apk = if is_host {
        AggregatePublicKey::new(&[verified_pk, peer_verified_pk])
    } else {
        AggregatePublicKey::new(&[peer_verified_pk, verified_pk])
    };

    println!("Keys exchanged and verified.");

    // 2. Shuffle
    let final_deck = if is_host {
        // Host shuffles first
        println!("Shuffling initial deck...");
        let (my_deck, my_proof) = shuffle.shuffle_initial_deck(&mut rng, apk, ctx);
        
        send_message(
            &mut stream,
            &Message::ShuffledDeck {
                deck: to_bytes(&my_deck),
                proof: to_bytes(&my_proof),
            },
        )?;
        println!("Sent initial shuffle. Waiting for peer shuffle...");

        let msg = recv_message(&mut stream)?;
        match msg {
            Message::ShuffledDeck { deck, proof } => {
                let peer_deck: PokerMaskedDeck = from_bytes(&deck)?;
                let peer_proof: PokerShuffleProof = from_bytes(&proof)?;
                
                // We need the verified version of our own deck to verify the peer's shuffle of it
                let my_vdeck = shuffle.verify_initial_shuffle(apk, my_deck, my_proof, ctx).unwrap();

                let final_vdeck = shuffle
                    .verify_shuffle(apk, &my_vdeck, peer_deck, peer_proof, ctx)
                    .ok_or_else(|| anyhow!("Peer shuffle verification failed"))?;
                println!("Shuffle complete and verified.");
                final_vdeck
            }
            _ => return Err(anyhow!("Expected ShuffledDeck")),
        }
    } else {
        // Guest waits for initial shuffle
        println!("Waiting for host shuffle...");
        let msg = recv_message(&mut stream)?;
        let initial_vdeck = match msg {
            Message::ShuffledDeck { deck, proof } => {
                let d: PokerMaskedDeck = from_bytes(&deck)?;
                let p: PokerShuffleProof = from_bytes(&proof)?;
                shuffle
                    .verify_initial_shuffle(apk, d, p, ctx)
                    .ok_or_else(|| anyhow!("Host initial shuffle verification failed"))?
            }
            _ => return Err(anyhow!("Expected ShuffledDeck")),
        };

        println!("Shuffling deck...");
        let (my_deck, my_proof) = shuffle.shuffle_deck(&mut rng, apk, &initial_vdeck, ctx);
        send_message(
            &mut stream,
            &Message::ShuffledDeck {
                deck: to_bytes(&my_deck),
                proof: to_bytes(&my_proof),
            },
        )?;
        
        // Guest needs to verify their own shuffle against the previous one to get the final verified deck handle?
        // Actually verify_shuffle returns Verified<MaskedDeck>.
        // We trust our own shuffle, but to get the type `Verified<MaskedDeck>`, we can just run verify.
        shuffle.verify_shuffle(apk, &initial_vdeck, my_deck, my_proof, ctx).unwrap()
    };

    // 3. Play Hand
    // Card Mapping:
    // 0,1: Host Hole
    // 2,3: Guest Hole
    // 4,5,6: Flop
    // 7: Turn
    // 8: River
    
    let mut my_hole_cards = Vec::new();
    let mut community_cards = Vec::new();
    
    // Reveal Hole Cards
    if is_host {
        println!("Dealing cards...");
        // Host gets 0, 1. Needs Guest tokens.
        for i in 0..2 {
            // Request token from Guest
            send_message(&mut stream, &Message::RequestToken { card_idx: i })?;
            let msg = recv_message(&mut stream)?;
            if let Message::Token { token, proof } = msg {
                let rt: RevealToken = from_bytes(&token)?;
                let rtp: RevealTokenProof = from_bytes(&proof)?;
                
                let card = final_deck.get(i).unwrap();
                let v_rt = rtp.verify(peer_verified_pk, rt, card, ctx)
                    .ok_or_else(|| anyhow!("Invalid reveal token from peer"))?;
                
                // My token
                let (my_rt, my_rtp) = card.reveal_token(&mut rng, &sk, pk, ctx);
                let my_v_rt = my_rtp.verify(verified_pk, my_rt, card, ctx).unwrap();
                
                let art = AggregateRevealToken::new(&[my_v_rt, v_rt]); // Host is 0, Guest is 1 in apk list?
                // Wait, order matters in AggregateRevealToken? 
                // Ziffle implementation: `pks.iter().map(|t| t.0.0.into_group()).sum()` -> It's just a sum. Order doesn't matter for addition.
                
                let card_idx = shuffle.reveal_card(art, card).unwrap();
                my_hole_cards.push(card_idx);
            } else {
                return Err(anyhow!("Expected Token"));
            }
        }
        
        // Guest gets 2, 3. Host provides tokens.
        for i in 2..4 {
            // Wait for request? Or just expect logic to mirror.
            // Let's assume standard flow: Host handles their cards, then helps Guest.
            // Guest will send RequestToken.
            let msg = recv_message(&mut stream)?;
            if let Message::RequestToken { card_idx } = msg {
                if card_idx != i { return Err(anyhow!("Unexpected card index requested")); }
                let card = final_deck.get(card_idx).unwrap();
                let (token, proof) = card.reveal_token(&mut rng, &sk, pk, ctx);
                send_message(&mut stream, &Message::Token {
                    token: to_bytes(&token),
                    proof: to_bytes(&proof),
                })?;
            } else {
                 return Err(anyhow!("Expected RequestToken"));
            }
        }
    } else {
        println!("Dealing cards...");
        // Guest: Host gets 0, 1. Guest provides tokens.
        for i in 0..2 {
            let msg = recv_message(&mut stream)?;
            if let Message::RequestToken { card_idx } = msg {
                if card_idx != i { return Err(anyhow!("Unexpected card index requested")); }
                let card = final_deck.get(card_idx).unwrap();
                let (token, proof) = card.reveal_token(&mut rng, &sk, pk, ctx);
                send_message(&mut stream, &Message::Token {
                    token: to_bytes(&token),
                    proof: to_bytes(&proof),
                })?;
            } else {
                 return Err(anyhow!("Expected RequestToken"));
            }
        }

        // Guest gets 2, 3. Needs Host tokens.
        for i in 2..4 {
            send_message(&mut stream, &Message::RequestToken { card_idx: i })?;
            let msg = recv_message(&mut stream)?;
            if let Message::Token { token, proof } = msg {
                let rt: RevealToken = from_bytes(&token)?;
                let rtp: RevealTokenProof = from_bytes(&proof)?;
                
                let card = final_deck.get(i).unwrap();
                let v_rt = rtp.verify(peer_verified_pk, rt, card, ctx)
                    .ok_or_else(|| anyhow!("Invalid reveal token from peer"))?;
                
                let (my_rt, my_rtp) = card.reveal_token(&mut rng, &sk, pk, ctx);
                let my_v_rt = my_rtp.verify(verified_pk, my_rt, card, ctx).unwrap();
                
                let art = AggregateRevealToken::new(&[v_rt, my_v_rt]); 
                
                let card_idx = shuffle.reveal_card(art, card).unwrap();
                my_hole_cards.push(card_idx);
            } else {
                return Err(anyhow!("Expected Token"));
            }
        }
    }

    println!("Your Hand: {}", format_cards(&my_hole_cards));

    // Betting Round 1 (Pre-flop)
    // Simplified: Just printing "Betting..." for now
    do_betting_round(&mut stream, is_host, "Pre-Flop")?;

    // Flop (4, 5, 6)
    println!("Dealing Flop...");
    let flop = reveal_community_cards(&mut stream, &mut rng, &shuffle, &final_deck, &sk, pk, verified_pk, peer_verified_pk, ctx, 4..7, is_host)?;
    community_cards.extend(flop);
    println!("Community: {}", format_cards(&community_cards));

    do_betting_round(&mut stream, is_host, "Flop")?;

    // Turn (7)
    println!("Dealing Turn...");
    let turn = reveal_community_cards(&mut stream, &mut rng, &shuffle, &final_deck, &sk, pk, verified_pk, peer_verified_pk, ctx, 7..8, is_host)?;
    community_cards.extend(turn);
    println!("Community: {}", format_cards(&community_cards));

    do_betting_round(&mut stream, is_host, "Turn")?;

    // River (8)
    println!("Dealing River...");
    let river = reveal_community_cards(&mut stream, &mut rng, &shuffle, &final_deck, &sk, pk, verified_pk, peer_verified_pk, ctx, 8..9, is_host)?;
    community_cards.extend(river);
    println!("Community: {}", format_cards(&community_cards));

    do_betting_round(&mut stream, is_host, "River")?;

    // Showdown - Reveal Hole Cards to each other
    // For now, just print what we have. A full game requires exchanging private tokens at the end.
    println!("Showdown!");
    println!("My Hand: {}", format_cards(&my_hole_cards));
    println!("Community: {}", format_cards(&community_cards));
    
    // In a real game, we would now exchange the tokens for our hole cards to prove our hand.
    // I'll skip that for this simplified prototype.

    Ok(())
}

fn reveal_community_cards(
    stream: &mut TcpStream,
    rng: &mut StdRng,
    shuffle: &PokerShuffle,
    deck: &Verified<PokerMaskedDeck>,
    sk: &SecretKey,
    pk: PublicKey,
    vpk: Verified<PublicKey>,
    peer_vpk: Verified<PublicKey>,
    ctx: &[u8],
    range: std::ops::Range<usize>,
    is_host: bool,
) -> Result<Vec<usize>> {
    let mut cards = Vec::new();
    for i in range {
        let card = deck.get(i).unwrap();
        
        // Both exchange tokens. 
        // Protocol: Host sends token first, then Guest sends token.
        let (my_rt, my_rtp) = card.reveal_token(rng, sk, pk, ctx);
        let my_v_rt = my_rtp.verify(vpk, my_rt, card, ctx).unwrap();

        let peer_rt;
        
        if is_host {
            send_message(stream, &Message::Token {
                token: to_bytes(&my_rt),
                proof: to_bytes(&my_rtp),
            })?;
            let msg = recv_message(stream)?;
            if let Message::Token { token, proof } = msg {
                let rt: RevealToken = from_bytes(&token)?;
                let rtp: RevealTokenProof = from_bytes(&proof)?;
                peer_rt = rtp.verify(peer_vpk, rt, card, ctx)
                    .ok_or_else(|| anyhow!("Invalid peer token"))?;
            } else {
                return Err(anyhow!("Expected Token"));
            }
        } else {
            let msg = recv_message(stream)?;
            let peer_token_msg = if let Message::Token { token, proof } = msg {
                 Some((token, proof))
            } else { None };
            
            if let Some((token, proof)) = peer_token_msg {
                let rt: RevealToken = from_bytes(&token)?;
                let rtp: RevealTokenProof = from_bytes(&proof)?;
                peer_rt = rtp.verify(peer_vpk, rt, card, ctx)
                    .ok_or_else(|| anyhow!("Invalid peer token"))?;
            } else {
                return Err(anyhow!("Expected Token"));
            }

            send_message(stream, &Message::Token {
                token: to_bytes(&my_rt),
                proof: to_bytes(&my_rtp),
            })?;
        }
        
        let art = AggregateRevealToken::new(&[my_v_rt, peer_rt]);
        let idx = shuffle.reveal_card(art, card).unwrap();
        cards.push(idx);
    }
    Ok(cards)
}

fn do_betting_round(stream: &mut TcpStream, is_host: bool, round_name: &str) -> Result<()> {
    println!("--- {} Betting Round (Mock) ---", round_name);
    // Real implementation would track state. 
    // For this prototype, we just exchange "Check" actions to proceed.
    
    if is_host {
        println!("You are first to act. Sending 'Check'.");
        send_message(stream, &Message::Action { action: GameAction::Check })?;
        let msg = recv_message(stream)?;
        println!("Peer sent: {:?}", msg);
    } else {
        println!("Waiting for peer...");
        let msg = recv_message(stream)?;
        println!("Peer sent: {:?}", msg);
        println!("Sending 'Check' back.");
        send_message(stream, &Message::Action { action: GameAction::Check })?;
    }
    Ok(())
}

fn format_cards(indices: &[usize]) -> String {
    indices.iter().map(|&idx| format_card(idx)).collect::<Vec<_>>().join(" ")
}

fn format_card(idx: usize) -> String {
    let suit = match idx / 13 {
        0 => "♣",
        1 => "♦",
        2 => "♥",
        3 => "♠",
        _ => "?",
    };
    let rank = match idx % 13 {
        0 => "2",
        1 => "3",
        2 => "4",
        3 => "5",
        4 => "6",
        5 => "7",
        6 => "8",
        7 => "9",
        8 => "10",
        9 => "J",
        10 => "Q",
        11 => "K",
        12 => "A",
        _ => "?",
    };
    format!("{}{}", rank, suit)
}