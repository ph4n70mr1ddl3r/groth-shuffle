const { run_simulation } = require('./pkg/rust_shuffle.js');

console.log("Starting Wasm Simulation...");
const start = Date.now();
run_simulation();
const end = Date.now();
console.log(`
Wasm Simulation Total Time: ${end - start} ms`);
