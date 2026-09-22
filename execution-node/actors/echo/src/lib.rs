wit_bindgen::generate!({ path: "../../wit", world: "actor" });

struct Echo;

impl exports::jkain::actor::handler::Guest for Echo {
    fn handle_request(request: Vec<u8>) -> Result<Vec<u8>, String> {
        Ok(request)
    }
}

export!(Echo);
