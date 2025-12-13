const factory = require('./build_wasm/groth_shuffle_js.js');

factory().then(Module => {
    console.log("=== WASM Groth Shuffle Benchmark ===");
    
    // 52 cards
    const numCards = 52;
    console.log(`Initializing benchmark for ${numCards} cards...`);
    
    const bench = new Module.Benchmark(numCards);
    
    console.log("Running Setup...");
    bench.setup();
    
    console.log("Running Shuffle...");
    const shuffleTime = bench.runShuffle();
    console.log(`Shuffle Time: ${shuffleTime.toFixed(2)} ms`);
    
    console.log("Running Verify...");
    const verifyTime = bench.runVerify();
    if (verifyTime < 0) {
        console.error("Verification FAILED!");
    } else {
        console.log(`Verify Time:  ${verifyTime.toFixed(2)} ms`);
    }
    
    console.log("====================================");
}).catch(err => {
    console.error("Failed to load WASM module:", err);
});
