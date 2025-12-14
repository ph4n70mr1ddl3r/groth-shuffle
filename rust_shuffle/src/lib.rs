mod simulation;

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn run_simulation() {
    simulation::run_simulation();
}
