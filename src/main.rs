use clap::{Parser, Subcommand};
use itsuku::{
    challenge_id::ChallengeId, config::Config, memory::Memory, merkle_tree::MerkleTree,
    proof::Proof,
};
use rand::{RngCore, rngs::ThreadRng};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Search for a proof of work
    Search {
        /// Number of memory chunks
        #[arg(long, default_value_t = 1 << 10)]
        chunk_count: usize,

        /// Size of each memory chunk
        #[arg(long, default_value_t = 1 << 15)]
        chunk_size: usize,

        /// Proof difficulty in bits
        #[arg(long, default_value_t = 24)]
        difficulty_bits: usize,

        /// Number of antecedents
        #[arg(long, default_value_t = 4)]
        antecedent_count: usize,

        /// Search path length
        #[arg(long, default_value_t = 9)]
        search_length: usize,

        /// Optional hex-encoded 64-byte challenge ID
        #[arg(long)]
        challenge_id: Option<String>,
    },

    /// Verify a proof (future use)
    Verify,
}

// -------------------------------
// Challenge ID helpers
// -------------------------------

fn build_random_challenge() -> ChallengeId {
    let mut bytes = [0u8; 64];
    let mut rng = ThreadRng::default();
    for i in 0..64 {
        bytes[i] = rng.next_u32() as u8;
    }
    ChallengeId {
        bytes: bytes.to_vec(),
    }
}

fn build_challenge_from_hex(hex_str: &str) -> ChallengeId {
    let decoded = hex::decode(hex_str).expect("Invalid hex string for --challenge-id");

    assert!(
        decoded.len() == 64,
        "--challenge-id must be exactly 64 bytes (128 hex chars)"
    );

    ChallengeId { bytes: decoded }
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Search {
            chunk_count,
            chunk_size,
            difficulty_bits,
            antecedent_count,
            search_length,
            challenge_id,
        } => {
            // Build config from CLI
            let mut config = Config::default();
            config.chunk_count = chunk_count;
            config.chunk_size = chunk_size;
            config.difficulty_bits = difficulty_bits;
            config.antecedent_count = antecedent_count;
            config.search_length = search_length;

            // Build challenge: either provided or random
            let challenge_id = match challenge_id {
                Some(hex_str) => build_challenge_from_hex(&hex_str),
                None => build_random_challenge(),
            };

            eprintln!("Challenge ID: {}", hex::encode(&challenge_id.bytes));

            // Build memory
            let mut memory = Memory::new(config);
            memory.build_all_chunks(&challenge_id);

            // Build Merkle tree
            let mut merkle_tree = MerkleTree::new(config);
            merkle_tree.compute_leaf_hashes(&challenge_id, &memory);
            merkle_tree.compute_intermediate_nodes(&challenge_id);

            // Run proof search
            let proof = Proof::search(config, &challenge_id, &memory, &merkle_tree);
            println!("{}", proof);
        }

        Commands::Verify => todo!(),
    }
}
