#[cfg(test)]
mod tests {
    use axum_test::TestServer;
    use keylo::config::Config;
    use keylo::startup::init_app_router_with_db_and_admin;
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    const RBAC_ADMIN_CLIENT_ID: &str = "cli-rbac-test";
    const RBAC_ADMIN_CLIENT_SECRET: &str = "CliRbacTest#123";

    async fn setup_test_server() -> Option<TestServer> {
        let config = Config::default();
        let db_url = std::env::var("TEST_DATABASE_URL").unwrap_or_else(|_| {
            "postgres://keylo_user:keylo_password@localhost:5432/keylo".to_string()
        });

        match init_app_router_with_db_and_admin(
            config,
            &db_url,
            RBAC_ADMIN_CLIENT_ID,
            RBAC_ADMIN_CLIENT_SECRET,
        )
        .await
        {
            Ok(router) => Some(TestServer::new(router)),
            Err(e) => {
                println!("Skipping test: DB unavailable ({})", e);
                None
            }
        }
    }

    async fn get_access_token(server: &TestServer) -> String {
        let login_response = server
            .post("/v1/admin/token")
            .json(&json!({
                "client_id": RBAC_ADMIN_CLIENT_ID,
                "client_secret": RBAC_ADMIN_CLIENT_SECRET
            }))
            .await;

        login_response.assert_status_ok();
        let body: serde_json::Value = login_response.json();
        body["access_token"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn test_create_role() {
        let Some(server) = setup_test_server().await else {
            return;
        };
        let token = get_access_token(&server).await;
        let role_name = format!(
            "admin-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()
        );

        let response = server
            .post("/api/rbac/roles")
            .add_header("Authorization", format!("Bearer {}", token))
            .json(&json!({
                "name": role_name,
                "description": "Administrator role"
            }))
            .await;

        assert_eq!(response.status_code(), 200);

        let body: serde_json::Value = response.json();
        assert!(body["success"].as_bool().unwrap());
        assert_eq!(body["data"]["name"], role_name);
    }

    #[tokio::test]
    async fn test_get_roles() {
        let Some(server) = setup_test_server().await else {
            return;
        };
        let token = get_access_token(&server).await;

        let response = server
            .get("/api/rbac/roles")
            .add_header("Authorization", format!("Bearer {}", token))
            .await;

        assert_eq!(response.status_code(), 200);

        let body: serde_json::Value = response.json();
        assert!(body["success"].as_bool().unwrap());
        assert!(body["data"].is_array());
    }

    #[tokio::test]
    async fn test_create_permission() {
        let Some(server) = setup_test_server().await else {
            return;
        };
        let token = get_access_token(&server).await;
        let permission_name = format!(
            "user.manage.{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis()
        );

        let response = server
            .post("/api/rbac/permissions")
            .add_header("Authorization", format!("Bearer {}", token))
            .json(&json!({
                "name": permission_name,
                "description": "Manage users permission"
            }))
            .await;

        assert_eq!(response.status_code(), 200);

        let body: serde_json::Value = response.json();
        assert!(body["success"].as_bool().unwrap());
        assert_eq!(body["data"]["name"], permission_name);
    }

    #[tokio::test]
    async fn test_get_permissions() {
        let Some(server) = setup_test_server().await else {
            return;
        };
        let token = get_access_token(&server).await;

        let response = server
            .get("/api/rbac/permissions")
            .add_header("Authorization", format!("Bearer {}", token))
            .await;

        assert_eq!(response.status_code(), 200);

        let body: serde_json::Value = response.json();
        assert!(body["success"].as_bool().unwrap());
        assert!(body["data"].is_array());
    }

    #[tokio::test]
    async fn test_batch_bindings_and_effective_permissions() {
        let Some(server) = setup_test_server().await else {
            return;
        };
        let token = get_access_token(&server).await;
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();

        let role_name = format!("ssc_dispatcher_{}", ts);
        let permission_read = format!("ssc.camera.read.{}", ts);
        let permission_write = format!("ssc.camera.write.{}", ts);
        let username = format!("prov_user_{}", ts);
        let email = format!("prov_user_{}@example.com", ts);

        let role_resp = server
            .post("/api/rbac/roles")
            .add_header("Authorization", format!("Bearer {}", token))
            .json(&json!({
                "name": role_name,
                "description": "dispatcher role"
            }))
            .await;
        role_resp.assert_status_ok();
        let role_body: serde_json::Value = role_resp.json();
        let role_id = role_body["data"]["id"].as_str().unwrap().to_string();

        let perm_read_resp = server
            .post("/api/rbac/permissions")
            .add_header("Authorization", format!("Bearer {}", token))
            .json(&json!({
                "name": permission_read,
                "description": "camera read"
            }))
            .await;
        perm_read_resp.assert_status_ok();
        let perm_read_body: serde_json::Value = perm_read_resp.json();
        let perm_read_id = perm_read_body["data"]["id"].as_str().unwrap().to_string();

        let perm_write_resp = server
            .post("/api/rbac/permissions")
            .add_header("Authorization", format!("Bearer {}", token))
            .json(&json!({
                "name": permission_write,
                "description": "camera write"
            }))
            .await;
        perm_write_resp.assert_status_ok();
        let perm_write_body: serde_json::Value = perm_write_resp.json();
        let perm_write_id = perm_write_body["data"]["id"].as_str().unwrap().to_string();

        let bind_perm_resp = server
            .post(&format!("/api/rbac/roles/{}/permissions/batch", role_id))
            .add_header("Authorization", format!("Bearer {}", token))
            .json(&json!({
                "permission_ids": [perm_read_id, perm_write_id]
            }))
            .await;
        bind_perm_resp.assert_status_ok();

        let provision_resp = server
            .post("/v1/admin/users/provision")
            .add_header("Authorization", format!("Bearer {}", token))
            .json(&json!({
                "username": username,
                "email": email,
                "password": "ProvisionPass123!",
                "role_ids": [role_id]
            }))
            .await;
        provision_resp.assert_status_ok();
        let provision_body: serde_json::Value = provision_resp.json();
        let user_id = provision_body["data"]["user"]["id"]
            .as_str()
            .unwrap()
            .to_string();

        let detail_resp = server
            .get(&format!("/api/rbac/roles/{}", role_id))
            .add_header("Authorization", format!("Bearer {}", token))
            .await;
        detail_resp.assert_status_ok();
        let detail_body: serde_json::Value = detail_resp.json();
        assert!(detail_body["data"]["permissions"].is_array());
        assert!(detail_body["data"]["permissions"].as_array().unwrap().len() >= 2);

        let effective_resp = server
            .get(&format!(
                "/v1/admin/users/{}/effective-permissions",
                user_id
            ))
            .add_header("Authorization", format!("Bearer {}", token))
            .await;
        effective_resp.assert_status_ok();
        let effective_body: serde_json::Value = effective_resp.json();
        assert!(effective_body["data"]["roles"].is_array());
        assert!(effective_body["data"]["permissions"].is_array());

        let prefix_resp = server
            .get("/api/rbac/permissions?prefix=ssc.camera")
            .add_header("Authorization", format!("Bearer {}", token))
            .await;
        prefix_resp.assert_status_ok();
        let prefix_body: serde_json::Value = prefix_resp.json();
        assert!(prefix_body["data"].is_array());
    }
}
