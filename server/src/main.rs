#[macro_use]
extern crate rocket;

use rocket::State;
use rocket::serde::json::Json;
use rs_merkle::{MerkleTree, algorithms::Sha256 as MerkleSha256};
use shared::{EncFile, RetrieveResponse, RetrieveResponseEnum, UploadResponse, hash_encfile};
use std::collections::HashMap;
use std::sync::Mutex;

struct ServerState {
    pub db: Mutex<HashMap<String, EncFile>>,
    pub current_id: Mutex<usize>,
    pub merkle_tree: Mutex<MerkleTree<MerkleSha256>>,
}

#[get("/")]
fn index() -> &'static str {
    "Welcome to skibidifiles (tm)!"
}

#[post("/file", format = "json", data = "<file>")]
fn upload_file(file: Json<EncFile>, state: &State<ServerState>) -> Json<UploadResponse> {
    let mut db = state.db.lock().unwrap();
    let mut current_id = state.current_id.lock().unwrap();
    let mut merkle_tree = state.merkle_tree.lock().unwrap();

    let file_data = file.into_inner();

    let hash = hash_encfile(&file_data);
    merkle_tree.insert(hash).commit();

    let id = current_id.to_string();
    db.insert(id.clone(), file_data);
    *current_id += 1;

    Json(UploadResponse { id })
}

#[get("/file/<id>")]
fn download_file(id: String, state: &State<ServerState>) -> Json<RetrieveResponseEnum> {
    let db = state.db.lock().unwrap();
    let merkle_tree = state.merkle_tree.lock().unwrap();
    let current_id = state.current_id.lock().unwrap();

    match db.get(&id) {
        Some(file) => {
            let proof = merkle_tree
                .proof(&[id.parse::<usize>().unwrap() - 1])
                .to_bytes();

            Json(RetrieveResponseEnum::Success(RetrieveResponse {
                proof,
                file: file.clone(),
                merkle_root: merkle_tree.root().unwrap(),
                merkle_tree_len: *current_id - 1,
            }))
        }
        None => Json(RetrieveResponseEnum::Error {
            error: "File not found".to_string(),
        }),
    }
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount("/", routes![index, upload_file, download_file])
        .manage(ServerState {
            db: Mutex::new(HashMap::new()),
            current_id: Mutex::new(1),
            merkle_tree: Mutex::new(MerkleTree::new()),
        })
}
