use base64::{Engine, prelude::BASE64_URL_SAFE};
use clap::{Parser, Subcommand};
use itsuku::{
    challenge_id::ChallengeId, config::Config, endianness::NativeEndian, memory::Memory,
    merkle_tree::MerkleTree, proof::Proof,
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
        #[command(flatten)]
        config: Config,
        #[arg(long)]
        challenge_id: Option<String>,
    },

    /// Verify a proof (reads JSON proof from stdin)
    Verify,
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
    ChallengeId { bytes: decoded }
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Search {
            config,
            challenge_id,
        } => run_search(config, challenge_id),
        Commands::Verify => run_verify(),
    }
}

fn run_search(config: Config, challenge_id_b64: Option<String>) {
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
    let mut memory = Memory::<NativeEndian>::new(config);
    memory.build_all_chunks(&challenge_id);
    eprintln!("SEARCH.MEMORY.BUILD.END");

    eprintln!("SEARCH.MERKLE.START");
    let mut merkle_tree = MerkleTree::<NativeEndian>::new(config);
    merkle_tree.compute_leaf_hashes(&challenge_id, &memory);
    merkle_tree.compute_intermediate_nodes(&challenge_id);
    eprintln!("SEARCH.MERKLE.END");

    eprintln!("SEARCH.PROOF.START");
    let proof = Proof::search(config, &challenge_id, &memory, &merkle_tree);
    eprintln!("SEARCH.PROOF.END");

    eprintln!("SEARCH.OUTPUT");
    serde_json::to_writer(stdout(), &proof).expect("Failed to serialize proof");
}

fn run_verify() {
    eprintln!("VERIFY.INPUT.START");
    let proof: Proof = serde_json::from_reader(stdin()).unwrap_or_else(|err| {
        eprintln!("VERIFY.INPUT.ERROR");
        eprintln!("error={}", err);
        std::process::exit(1);
    });
    eprintln!("VERIFY.INPUT.END");

    eprintln!("VERIFY.EXEC.START");
    let result = proof.verify();
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
