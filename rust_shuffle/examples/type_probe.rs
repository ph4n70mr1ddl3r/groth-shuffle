use ziffle::*;
use ark_std::rand::SeedableRng;

fn main() {
    let mut rng = ark_std::rand::rngs::StdRng::from_seed([0u8; 32]);
    let shuffle = Shuffle::<52>::default();
    let ctx = b"context";
    
    // Keygen
    let (sk, pk, proof) = shuffle.keygen(&mut rng, ctx);
    // Force type error to see names
    let _: () = pk;
    let _: () = proof;
    let vpk = proof.verify(pk, ctx).unwrap();
    let _: () = vpk;

    // Shuffle
    let apk = AggregatePublicKey::new(&[vpk]);
    let (deck, s_proof) = shuffle.shuffle_initial_deck(&mut rng, apk, ctx);
    let _: () = deck;
    let _: () = s_proof;
    
    let vdeck = shuffle.verify_initial_shuffle(apk, deck, s_proof, ctx).unwrap();
    let _: () = vdeck;
    
    let card = vdeck.get(0).unwrap();
    let (token, r_proof) = card.reveal_token(&mut rng, &sk, pk, ctx);
    let _: () = token;
    let _: () = r_proof;
    
    let vtoken = r_proof.verify(vpk, token, card, ctx).unwrap();
    let _: () = vtoken;
}
