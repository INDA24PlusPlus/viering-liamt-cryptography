#[macro_use]
extern crate rocket;

use rocket::State;
use rocket::serde::json::Json;
use shared::{EncFile, EncFileResponse};
use std::collections::HashMap;
use std::sync::Mutex;

struct ServerState {
    pub db: Mutex<HashMap<String, EncFile>>,
    pub current_id: Mutex<u64>,
}

#[get("/")]
fn index() -> &'static str {
    "welcome to skibidifiles (tm)!"
}

#[post("/file", format = "json", data = "<file>")]
fn upload_file(file: Json<EncFile>, state: &State<ServerState>) -> String {
    println!("file: {:?} {:?} {:?}", file.data, file.nonce, file.tag);

    let mut db = state.db.lock().unwrap();
    let mut current_id = state.current_id.lock().unwrap();

    let id = current_id.to_string();

    db.insert(id.clone(), file.into_inner());
    *current_id += 1;

    id
}

#[get("/file/<id>")]
fn download_file(id: String, state: &State<ServerState>) -> Json<EncFileResponse> {
    let db = state.db.lock().unwrap();
    match db.get(&id) {
        Some(file) => {
            println!("file: {:?} {:?} {:?}", file.data, file.nonce, file.tag);
            Json(EncFileResponse::Success((*file).clone()))
        }
        None => Json(EncFileResponse::Error {
            error: "file not found".to_string(),
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
        })
}
