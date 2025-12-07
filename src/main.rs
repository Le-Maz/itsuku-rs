use clap::{Parser, Subcommand};
use itsuku::{
    challenge_id::ChallengeId, config::Config, memory::Memory, merkle_tree::MerkleTree,
    proof::Proof,
};

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
    },
    /// Verify a proof (future use)
    Verify,
}

fn build_test_challenge() -> ChallengeId {
    let mut bytes = [0u8; 64];
    for i in 0..64 {
        bytes[i] = i as u8;
    }
    ChallengeId {
        bytes: bytes.to_vec(),
    }
}

fn main() {
    let cli = Cli::parse();

    // Config setup
    let mut config = Config::default();
    config.chunk_count = 16;
    config.chunk_size = 128;
    config.difficulty_bits = 16;

    let challenge_id = build_test_challenge();
    let mut memory = Memory::new(config);
    memory.build_all_chunks(&challenge_id);

    let mut merkle_tree = MerkleTree::new(config);
    merkle_tree.compute_leaf_hashes(&challenge_id, &memory);
    merkle_tree.compute_intermediate_nodes(&challenge_id);

    match cli.command {
        Commands::Search {
            chunk_count,
            chunk_size,
            difficulty_bits,
            antecedent_count,
            search_length,
        } => {
            let mut config = Config::default();
            config.chunk_count = chunk_count;
            config.chunk_size = chunk_size;
            config.difficulty_bits = difficulty_bits;
            config.antecedent_count = antecedent_count;
            config.search_length = search_length;

            let challenge_id = build_test_challenge();

            let mut memory = Memory::new(config);
            memory.build_all_chunks(&challenge_id);

            let mut merkle_tree = MerkleTree::new(config);
            merkle_tree.compute_leaf_hashes(&challenge_id, &memory);
            merkle_tree.compute_intermediate_nodes(&challenge_id);

            let proof = Proof::search(config, &challenge_id, &memory, &merkle_tree);
            println!("Found proof: {:?}", proof);
        }
        Commands::Verify => todo!(),
    }
}
