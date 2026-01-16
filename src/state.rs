use std::collections::HashMap;
use std::sync::Arc;
use crate::models::Keys;

#[derive(Clone)]
pub struct AppState {
    pub jwt_keys: Keys,
    pub clients: Arc<HashMap<String, String>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    pub fn new() -> Self {
        let jwt_secret =
            std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");

        let mut clients = HashMap::new();
        clients.insert("web".into(), "web-secret".into());
        clients.insert("cli".into(), "cli-secret".into());

        Self {
            jwt_keys: Keys::new(jwt_secret.as_bytes()),
            clients: Arc::new(clients), // Arc 放在字段里，而不是 State 外面
        }
    }
}
