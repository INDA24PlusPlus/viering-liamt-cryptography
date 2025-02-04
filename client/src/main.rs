use clap::{Parser, Subcommand};
use crypto::{
    aead::{AeadDecryptor, AeadEncryptor},
    aes::KeySize,
    aes_gcm,
};
use rand::Rng;
use reqwest::blocking::Client;
use sha2::{Digest, Sha256};
use shared::{EncFile, EncFileResponse};
use std::{path::PathBuf, process::exit};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: CliCommand,
}

#[derive(Subcommand)]
enum CliCommand {
    Upload(UploadArgs),
    Retrieve(RetrieveArgs),
}

#[derive(Parser)]
struct UploadArgs {
    #[arg(required = true)]
    file: PathBuf,
    #[arg(required = true)]
    password: String,
}

#[derive(Parser)]
struct RetrieveArgs {
    #[arg(required = true)]
    id: u16,
    #[arg(required = true)]
    password: String,
    /// Output file stored in the specified path.
    #[arg(short, long)]
    out: Option<PathBuf>,
}

fn main() {
    let cli = Cli::parse();

    match &cli.command {
        CliCommand::Upload(upload_args) => upload(upload_args),
        CliCommand::Retrieve(retrieve_args) => retrieve(retrieve_args),
    };
}

fn upload(upload_args: &UploadArgs) {
    println!("Uploading file: {}", upload_args.file.display());

    let content = read_file(&upload_args.file);

    let key = derive_key(&upload_args.password);

    let enc = encrypt(&content, &key);

    let client = Client::new();
    let res = client
        .post("http://localhost:8000/file")
        .json(&enc)
        .send()
        .unwrap();

    println!(
        "File successfully uploaded with id: {:?}",
        res.text().unwrap()
    );
}

fn retrieve(retrieve_args: &RetrieveArgs) {
    println!("retrieving file: {}", retrieve_args.id);

    let client = Client::new();
    let res = client
        .get(format!("http://localhost:8000/file/{}", retrieve_args.id))
        .send()
        .unwrap();

    let res: EncFileResponse = res.json().unwrap();
    match res {
        EncFileResponse::Success(file) => {
            let key = derive_key(&retrieve_args.password);
            let dec = decrypt(&file, &key);

            match &retrieve_args.out {
                Some(out) => {
                    std::fs::write(out, dec).unwrap();
                    println!("File successfully written to: {}", out.display());
                }
                None => {
                    println!("File contents: {:?}", String::from_utf8(dec).unwrap());
                }
            }
        }
        EncFileResponse::Error { error } => {
            println!("Error: {}", error);
        }
    }
}

fn read_file(file: &PathBuf) -> Vec<u8> {
    match std::fs::read(file) {
        Ok(content) => content,
        Err(err) => {
            println!("Error reading file: {}", err);
            exit(0);
        }
    }
}

fn derive_key(password: &str) -> [u8; 32] {
    Sha256::digest(password.as_bytes())
        .as_slice()
        .try_into()
        .unwrap()
}

fn encrypt(data: &Vec<u8>, key: &[u8; 32]) -> EncFile {
    let mut rng = rand::rng();
    let mut nonce = [0u8; 12];
    rng.fill(&mut nonce);

    let mut enc = aes_gcm::AesGcm::new(KeySize::KeySize256, key, &nonce, &[]);

    let input = data.as_slice();
    let mut output = vec![0u8; input.len()];

    let mut tag = [0u8; 16];

    enc.encrypt(input, &mut output, &mut tag);

    EncFile {
        nonce,
        tag,
        data: output,
        id: -1,
    }
}

fn decrypt(file: &EncFile, key: &[u8; 32]) -> Vec<u8> {
    let mut dec = aes_gcm::AesGcm::new(KeySize::KeySize256, key, &file.nonce, &[]);

    let mut output = vec![0u8; file.data.len()];
    dec.decrypt(&file.data, &mut output, &file.tag);

    if output.iter().all(|&x| x == 0) {
        println!("Invalid password");
        exit(0);
    }

    output.to_vec()
}
