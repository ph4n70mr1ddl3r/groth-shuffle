use ziffle::{
    Shuffle, AggregatePublicKey, AggregateRevealToken, 
    Verified, PublicKey, SecretKey, MaskedDeck, ShuffleProof, 
    OwnershipProof, RevealToken, RevealTokenProof, MaskedCard
};
use ark_std::rand::SeedableRng;

#[cfg(not(target_arch = "wasm32"))]
use std::time::Instant;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

// --- Platform Abstraction ---

#[cfg(not(target_arch = "wasm32"))]
fn get_time_ms() -> f64 {
    // Return time in ms (relative to some start, doesn't matter for diff)
    // We can't easily convert Instant to f64 absolute, so we'll just handle diffs locally 
    // or use a hack. Actually, simpler:
    // Let's just return 0.0 here and let the specific measure blocks handle it? 
    // No, we want a unified interface.
    // We'll trust the specific blocks to use Instant on native.
    0.0 
}

#[cfg(target_arch = "wasm32")]
fn get_time_ms() -> f64 {
    js_sys::Date::now()
}

#[cfg(not(target_arch = "wasm32"))]
fn console_log(s: &str) {
    println!("{}", s);
}

#[cfg(target_arch = "wasm32")]
fn console_log(s: &str) {
    web_sys::console::log_1(&JsValue::from_str(s));
}

// --- Helper Utilities ---

pub fn card_name(index: usize) -> String {
    let ranks = ["2", "3", "4", "5", "6", "7", "8", "9", "T", "J", "Q", "K", "A"];
    let suits = ["c", "d", "h", "s"];
    format!("{}{}", ranks[index % 13], suits[index / 13])
}

fn log_msg(from: &str, to: &str, msg_type: &str, payload: &str, size: usize, time_ms: f64) {
    console_log(&format!("  [MSG] {:<10} -> {:<10} | Type: {:<20}", from, to, msg_type));
    console_log(&format!("        Payload: {}", payload));
    console_log(&format!("        Size: {} bytes | Time: {:.2} ms", size, time_ms));
}

// --- Actors ---

pub struct Player {
    id: usize,
    name: String,
    sk: Option<SecretKey>,
    pk: Option<PublicKey>,
}

impl Player {
    pub fn new(id: usize) -> Self {
        Player {
            id,
            name: format!("Player{}", id + 1),
            sk: None,
            pk: None,
        }
    }

    fn handle_handshake(&mut self, shuffle: &Shuffle<52>, ctx: &[u8]) -> (PublicKey, OwnershipProof) {
        #[cfg(not(target_arch = "wasm32"))]
        let start = Instant::now();
        #[cfg(target_arch = "wasm32")]
        let start = get_time_ms();
        
        let mut rng = ark_std::rand::rngs::StdRng::from_seed([self.id as u8; 32]);
        
        let (sk, pk, proof) = shuffle.keygen(&mut rng, ctx);
        self.sk = Some(sk);
        self.pk = Some(pk);

        #[cfg(not(target_arch = "wasm32"))]
        let time = start.elapsed().as_secs_f64() * 1000.0;
        #[cfg(target_arch = "wasm32")]
        let time = get_time_ms() - start;
        
        log_msg(&self.name, "Server", "HANDSHAKE_RESP", "PublicKey + Proof", 97, time);
        
        (pk, proof)
    }

    fn handle_shuffle(&self, shuffle: &Shuffle<52>, apk: &AggregatePublicKey, input_deck: &Verified<MaskedDeck<52>>, ctx: &[u8], is_first: bool) 
        -> (MaskedDeck<52>, ShuffleProof<52>) 
    {
        #[cfg(not(target_arch = "wasm32"))]
        let start = Instant::now();
        #[cfg(target_arch = "wasm32")]
        let start = get_time_ms();

        let mut rng = ark_std::rand::rngs::StdRng::from_seed([self.id as u8 + 10; 32]);

        let (deck, proof) = if is_first {
            shuffle.shuffle_initial_deck(&mut rng, *apk, ctx)
        } else {
            shuffle.shuffle_deck(&mut rng, *apk, input_deck, ctx)
        };

        #[cfg(not(target_arch = "wasm32"))]
        let time = start.elapsed().as_secs_f64() * 1000.0;
        #[cfg(target_arch = "wasm32")]
        let time = get_time_ms() - start;
        
        let size = 3500 + (52 * 66); 
        log_msg(&self.name, "Server", "SHUFFLE_RESP", "New Deck + Bayer-Groth Proof", size, time);

        (deck, proof)
    }

    fn handle_decrypt_share(&self, card: &MaskedCard, ctx: &[u8]) 
        -> (RevealToken, RevealTokenProof) 
    {
        #[cfg(not(target_arch = "wasm32"))]
        let start = Instant::now();
        #[cfg(target_arch = "wasm32")]
        let start = get_time_ms();

        let sk = self.sk.as_ref().expect("Handshake not done");
        let pk = self.pk.expect("Handshake not done");
        let mut rng = ark_std::rand::rngs::StdRng::from_seed([self.id as u8 + 50; 32]);

        let (token, proof) = card.reveal_token(&mut rng, sk, pk, ctx);

        #[cfg(not(target_arch = "wasm32"))]
        let time = start.elapsed().as_secs_f64() * 1000.0;
        #[cfg(target_arch = "wasm32")]
        let time = get_time_ms() - start;

        log_msg(&self.name, "Server", "DECRYPT_SHARE_RESP", "Token + ZKProof", 96, time);

        (token, proof)
    }
}

// --- Server ---

pub struct Server {
    players: Vec<Player>,
    shuffle_ctx: Shuffle<52>,
    apk: Option<AggregatePublicKey>,
    verified_pks: Vec<Verified<PublicKey>>,
    current_deck: Option<Verified<MaskedDeck<52>>>,
    ctx: &'static [u8],
}

impl Server {
    pub fn new() -> Self {
        Server {
            players: Vec::new(),
            shuffle_ctx: Shuffle::<52>::default(),
            apk: None,
            verified_pks: Vec::new(),
            current_deck: None,
            ctx: b"poker_simulation_v1",
        }
    }

    pub fn register(&mut self, p: Player) {
        self.players.push(p);
    }

    pub fn run(&mut self) {
        console_log("=== [Server] Initializing Hand (Ziffle/Groth12) ===\n");

        console_log("--- Handshake Phase ---");
        for i in 0..self.players.len() {
            log_msg("Server", &self.players[i].name, "HANDSHAKE_REQ", "Context", 0, 0.0);
            let (pk, proof) = self.players[i].handle_handshake(&self.shuffle_ctx, self.ctx);
            let vpk = proof.verify(pk, self.ctx).expect("Invalid Key Proof!");
            self.verified_pks.push(vpk);
        }
        self.apk = Some(AggregatePublicKey::new(&self.verified_pks));

        console_log("\n--- Shuffle Phase ---");
        
        log_msg("Server", &self.players[0].name, "SHUFFLE_REQ", "Initial Deck", 0, 0.0);
        
        #[cfg(not(target_arch = "wasm32"))]
        let start = Instant::now();
        #[cfg(target_arch = "wasm32")]
        let start = get_time_ms();

        let mut rng1 = ark_std::rand::rngs::StdRng::from_seed([10u8; 32]);
        let (d1, p1) = self.shuffle_ctx.shuffle_initial_deck(&mut rng1, *self.apk.as_ref().unwrap(), self.ctx);
        
        #[cfg(not(target_arch = "wasm32"))]
        let time1 = start.elapsed().as_secs_f64() * 1000.0;
        #[cfg(target_arch = "wasm32")]
        let time1 = get_time_ms() - start;

        log_msg(&self.players[0].name, "Server", "SHUFFLE_RESP", "New Deck + Bayer-Groth Proof", 3500+52*66, time1);

        #[cfg(not(target_arch = "wasm32"))]
        let start_v = Instant::now();
        #[cfg(target_arch = "wasm32")]
        let start_v = get_time_ms();

        let vd1 = self.shuffle_ctx.verify_initial_shuffle(*self.apk.as_ref().unwrap(), d1, p1, self.ctx).expect("P1 Shuffle Failed");
        
        #[cfg(not(target_arch = "wasm32"))]
        let time_v = start_v.elapsed().as_secs_f64() * 1000.0;
        #[cfg(target_arch = "wasm32")]
        let time_v = get_time_ms() - start_v;

        console_log(&format!("   [Server] P1 Shuffle Verified in {:.2} ms", time_v));
        self.current_deck = Some(vd1);

        log_msg("Server", &self.players[1].name, "SHUFFLE_REQ", "P1 Deck", 3500, 0.0);
        let (d2, p2) = self.players[1].handle_shuffle(&self.shuffle_ctx, self.apk.as_ref().unwrap(), self.current_deck.as_ref().unwrap(), self.ctx, false);

        #[cfg(not(target_arch = "wasm32"))]
        let start_v2 = Instant::now();
        #[cfg(target_arch = "wasm32")]
        let start_v2 = get_time_ms();

        let vd2 = self.shuffle_ctx.verify_shuffle(*self.apk.as_ref().unwrap(), self.current_deck.as_ref().unwrap(), d2, p2, self.ctx).expect("P2 Shuffle Failed");
        
        #[cfg(not(target_arch = "wasm32"))]
        let time_v2 = start_v2.elapsed().as_secs_f64() * 1000.0;
        #[cfg(target_arch = "wasm32")]
        let time_v2 = get_time_ms() - start_v2;

        console_log(&format!("   [Server] P2 Shuffle Verified in {:.2} ms", time_v2));
        self.current_deck = Some(vd2);

        console_log("\n--- Dealing Phase ---");
        let mut card_idx = 0;
        
        self.deal_private(0, card_idx); card_idx += 1;
        self.deal_private(1, card_idx); card_idx += 1;
        self.deal_private(0, card_idx); card_idx += 1;
        self.deal_private(1, card_idx); card_idx += 1;

        card_idx += 1;
        console_log("\n--- Flop ---");
        self.reveal_public(card_idx, "Flop 1"); card_idx += 1;
        self.reveal_public(card_idx, "Flop 2"); card_idx += 1;
        self.reveal_public(card_idx, "Flop 3"); card_idx += 1;

        card_idx += 1;
        console_log("\n--- Turn ---");
        self.reveal_public(card_idx, "Turn"); card_idx += 1;

        card_idx += 1;
        console_log("\n--- River ---");
        self.reveal_public(card_idx, "River");

        console_log("\n--- Showdown ---");
        self.reveal_public(0, "P1 Hole 1");
        self.reveal_public(2, "P1 Hole 2");
        self.reveal_public(1, "P2 Hole 1");
        self.reveal_public(3, "P2 Hole 2");
    }

    fn deal_private(&self, target_idx: usize, card_idx: usize) {
        let deck = self.current_deck.as_ref().unwrap();
        let card = deck.get(card_idx).unwrap();
        let target = &self.players[target_idx];
        console_log(&format!("Server: Private deal to {}", target.name));

        let mut tokens = Vec::new();
        for (i, p) in self.players.iter().enumerate() {
            log_msg("Server", &p.name, "DECRYPT_SHARE_REQ", "Card Index", 0, 0.0);
            let (token, proof) = p.handle_decrypt_share(&card, self.ctx);
            let vtoken = proof.verify(self.verified_pks[i], token, card, self.ctx).expect("Invalid Decryption Share");
            tokens.push(vtoken);
        }

        let agg_token = AggregateRevealToken::new(&tokens);
        let val = self.shuffle_ctx.reveal_card(agg_token, card).unwrap();
        console_log(&format!("   -> {} sees: {}", target.name, card_name(val)));
    }

    fn reveal_public(&self, card_idx: usize, label: &str) {
        let deck = self.current_deck.as_ref().unwrap();
        let card = deck.get(card_idx).unwrap();
        
        let mut tokens = Vec::new();
        for (i, p) in self.players.iter().enumerate() {
            let (token, proof) = p.handle_decrypt_share(&card, self.ctx);
            let vtoken = proof.verify(self.verified_pks[i], token, card, self.ctx).expect("Invalid Decryption Share");
            tokens.push(vtoken);
        }

        let agg_token = AggregateRevealToken::new(&tokens);
        let val = self.shuffle_ctx.reveal_card(agg_token, card).unwrap();
        console_log(&format!("   -> PUBLIC {}: {}", label, card_name(val)));
    }
}

pub fn run_simulation() {
    let mut server = Server::new();
    server.register(Player::new(0));
    server.register(Player::new(1));
    server.run();
}

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    run_simulation();
}