use std::collections::HashMap;
use crate::models::Keys;

pub struct AppState {
    pub jwt_keys: Keys,
    pub clients: HashMap<String, String>,
}
