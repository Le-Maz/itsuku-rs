use base64::{Engine, prelude::BASE64_URL_SAFE};
use clap::{Parser, Subcommand};
use itsuku::{
    challenge_id::ChallengeId, config::Config, memory::Memory, merkle_tree::MerkleTree,
    proof::Proof,
};
use rand::{RngCore, rngs::ThreadRng};
use std::io::{stdin, stdout};

#[derive(Parser)]
#[command(author, version, about = "CLI for the Itsuku Proof-of-Work scheme")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Search for a valid proof of work given the parameters
    Search {
        #[arg(long, default_value_t = 1 << 10)]
        chunk_count: usize,
        #[arg(long, default_value_t = 1 << 15)]
        chunk_size: usize,
        #[arg(long, default_value_t = 24)]
        difficulty_bits: usize,
        #[arg(long, default_value_t = 4)]
        antecedent_count: usize,
        #[arg(long, default_value_t = 9)]
        search_length: usize,
        #[arg(long)]
        challenge_id: Option<String>,
    },

    /// Verify a proof (reads JSON proof from stdin)
    Verify {
        #[arg(long, default_value_t = 1 << 10)]
        chunk_count: usize,
        #[arg(long, default_value_t = 1 << 15)]
        chunk_size: usize,
        #[arg(long, default_value_t = 24)]
        difficulty_bits: usize,
        #[arg(long, default_value_t = 4)]
        antecedent_count: usize,
        #[arg(long, default_value_t = 9)]
        search_length: usize,
        #[arg(long)]
        challenge_id: String,
    },
}

// -------------------------------
// Challenge ID helpers
// -------------------------------

fn build_random_challenge() -> ChallengeId {
    let mut bytes = [0u8; 64];
    ThreadRng::default().fill_bytes(&mut bytes);
    ChallengeId {
        bytes: bytes.to_vec(),
    }
}

fn build_challenge_from_b64(b64_str: &str) -> ChallengeId {
    let decoded = BASE64_URL_SAFE
        .decode(b64_str)
        .expect("Invalid b64 string for --challenge-id");
    if decoded.len() != 64 {
        panic!(
            "--challenge-id must be exactly 64 bytes (128 b64 chars), got {} bytes",
            decoded.len()
        );
    }
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
        } => run_search(
            chunk_count,
            chunk_size,
            difficulty_bits,
            antecedent_count,
            search_length,
            challenge_id,
        ),
        Commands::Verify {
            chunk_count,
            chunk_size,
            difficulty_bits,
            antecedent_count,
            search_length,
            challenge_id,
        } => run_verify(
            chunk_count,
            chunk_size,
            difficulty_bits,
            antecedent_count,
            search_length,
            challenge_id,
        ),
    }
}

fn run_search(
    chunk_count: usize,
    chunk_size: usize,
    difficulty_bits: usize,
    antecedent_count: usize,
    search_length: usize,
    challenge_id_b64: Option<String>,
) {
    let config = Config {
        chunk_count,
        chunk_size,
        difficulty_bits,
        antecedent_count,
        search_length,
    };

    let challenge_id = match challenge_id_b64 {
        Some(b64_str) => build_challenge_from_b64(&b64_str),
        None => build_random_challenge(),
    };

    eprintln!("SEARCH.CONFIG.START");
    eprintln!(
        "challenge_id={}",
        BASE64_URL_SAFE.encode(&challenge_id.bytes)
    );
    eprintln!("chunk_count={}", config.chunk_count);
    eprintln!("chunk_size={}", config.chunk_size);
    eprintln!("difficulty_bits={}", config.difficulty_bits);
    eprintln!("antecedent_count={}", config.antecedent_count);
    eprintln!("search_length={}", config.search_length);
    eprintln!("SEARCH.CONFIG.END");

    eprintln!("SEARCH.MEMORY.BUILD.START");
    let mut memory = Memory::new(config);
    memory.build_all_chunks(&challenge_id);
    eprintln!("SEARCH.MEMORY.BUILD.END");

    eprintln!("SEARCH.MERKLE.START");
    let mut merkle_tree = MerkleTree::new(config);
    merkle_tree.compute_leaf_hashes(&challenge_id, &memory);
    merkle_tree.compute_intermediate_nodes(&challenge_id);
    eprintln!("SEARCH.MERKLE.END");

    eprintln!("SEARCH.PROOF.START");
    let proof = Proof::search(config, &challenge_id, &memory, &merkle_tree);
    eprintln!("SEARCH.PROOF.END");

    eprintln!("SEARCH.OUTPUT");
    serde_json::to_writer(stdout(), &proof).expect("Failed to serialize proof");
}

fn run_verify(
    chunk_count: usize,
    chunk_size: usize,
    difficulty_bits: usize,
    antecedent_count: usize,
    search_length: usize,
    challenge_id_b64: String,
) {
    let config = Config {
        chunk_count,
        chunk_size,
        difficulty_bits,
        antecedent_count,
        search_length,
    };
    let challenge_id = build_challenge_from_b64(&challenge_id_b64);

    eprintln!("VERIFY.CONFIG.START");
    eprintln!(
        "challenge_id={}",
        BASE64_URL_SAFE.encode(&challenge_id.bytes)
    );
    eprintln!("chunk_count={}", config.chunk_count);
    eprintln!("chunk_size={}", config.chunk_size);
    eprintln!("difficulty_bits={}", config.difficulty_bits);
    eprintln!("antecedent_count={}", config.antecedent_count);
    eprintln!("search_length={}", config.search_length);
    eprintln!("VERIFY.CONFIG.END");

    eprintln!("VERIFY.INPUT.START");
    let proof: Proof = serde_json::from_reader(stdin()).unwrap_or_else(|err| {
        eprintln!("VERIFY.INPUT.ERROR");
        eprintln!("error={}", err);
        std::process::exit(1);
    });
    eprintln!("VERIFY.INPUT.END");

    eprintln!("VERIFY.EXEC.START");
    let result = proof.verify(&config, &challenge_id);
    eprintln!("VERIFY.EXEC.END");

    match result {
        Ok(()) => {
            eprintln!("VALID");
            eprintln!("VERIFY.RESULT");
            eprintln!("valid=true");
        }
        Err(error) => {
            eprintln!("INVALID");
            eprintln!("VERIFY.RESULT");
            eprintln!("valid=false");
            eprintln!("reason={}", error);
            std::process::exit(1);
        }
    }
}
