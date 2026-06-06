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
        let db_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://keylo_user@localhost:5432/keylo".to_string());

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

    async fn get_or_create_permission_id(
        server: &TestServer,
        token: &str,
        permission_name: &str,
        description: &str,
    ) -> String {
        let create_resp = server
            .post("/api/rbac/permissions")
            .add_header("Authorization", format!("Bearer {}", token))
            .json(&json!({
                "name": permission_name,
                "description": description
            }))
            .await;

        if create_resp.status_code().is_success() {
            let body: serde_json::Value = create_resp.json();
            return body["data"]["id"].as_str().unwrap().to_string();
        }

        let list_resp = server
            .get(&format!("/api/rbac/permissions?prefix={}", permission_name))
            .add_header("Authorization", format!("Bearer {}", token))
            .await;
        list_resp.assert_status_ok();
        let body: serde_json::Value = list_resp.json();
        body["data"]
            .as_array()
            .unwrap()
            .iter()
            .find(|permission| permission["name"] == permission_name)
            .and_then(|permission| permission["id"].as_str())
            .unwrap()
            .to_string()
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

    #[tokio::test]
    async fn test_user_role_assignment_rejects_service_only_roles_without_lingering_binding() {
        let Some(server) = setup_test_server().await else {
            return;
        };
        let token = get_access_token(&server).await;
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();

        let role_name = format!("service_only_{}", ts);
        let role_resp = server
            .post("/api/rbac/roles")
            .add_header("Authorization", format!("Bearer {}", token))
            .json(&json!({
                "name": role_name,
                "description": "service-only role",
                "assignable_to": "service"
            }))
            .await;
        role_resp.assert_status_ok();
        let role_body: serde_json::Value = role_resp.json();
        let role_id = role_body["data"]["id"].as_str().unwrap().to_string();

        let rejected_provision_resp = server
            .post("/v1/admin/users/provision")
            .add_header("Authorization", format!("Bearer {}", token))
            .json(&json!({
                "username": format!("invalid_prov_{}", ts),
                "email": format!("invalid_prov_{}@example.com", ts),
                "password": "ProvisionPass123!",
                "role_ids": [role_id.clone()]
            }))
            .await;
        assert_eq!(
            rejected_provision_resp.status_code(),
            axum::http::StatusCode::BAD_REQUEST
        );
        let rejected_provision_body: serde_json::Value = rejected_provision_resp.json();
        assert_eq!(rejected_provision_body["error"], "invalid_role_assignment");

        let provision_resp = server
            .post("/v1/admin/users/provision")
            .add_header("Authorization", format!("Bearer {}", token))
            .json(&json!({
                "username": format!("assign_target_{}", ts),
                "email": format!("assign_target_{}@example.com", ts),
                "password": "ProvisionPass123!"
            }))
            .await;
        provision_resp.assert_status_ok();
        let provision_body: serde_json::Value = provision_resp.json();
        let user_id = provision_body["data"]["user"]["id"]
            .as_str()
            .unwrap()
            .to_string();

        let assign_resp = server
            .post(&format!("/api/rbac/users/{}/roles", user_id))
            .add_header("Authorization", format!("Bearer {}", token))
            .json(&json!({ "role_id": role_id.clone() }))
            .await;
        assert_eq!(
            assign_resp.status_code(),
            axum::http::StatusCode::BAD_REQUEST
        );
        let assign_body: serde_json::Value = assign_resp.json();
        assert_eq!(assign_body["error"], "invalid_role_assignment");

        let roles_resp = server
            .get(&format!("/api/rbac/users/{}/roles", user_id))
            .add_header("Authorization", format!("Bearer {}", token))
            .await;
        roles_resp.assert_status_ok();
        let roles_body: serde_json::Value = roles_resp.json();
        assert!(!roles_body["data"]
            .as_array()
            .unwrap()
            .iter()
            .any(|role| role["id"] == role_id));
    }

    #[tokio::test]
    async fn test_role_assignable_to_update_rejects_existing_incompatible_bindings() {
        let Some(server) = setup_test_server().await else {
            return;
        };
        let token = get_access_token(&server).await;
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();

        let role_name = format!("user_bound_then_service_{}", ts);
        let role_resp = server
            .post("/api/rbac/roles")
            .add_header("Authorization", format!("Bearer {}", token))
            .json(&json!({
                "name": role_name,
                "description": "role with existing user binding"
            }))
            .await;
        role_resp.assert_status_ok();
        let role_body: serde_json::Value = role_resp.json();
        let role_id = role_body["data"]["id"].as_str().unwrap().to_string();

        let provision_resp = server
            .post("/v1/admin/users/provision")
            .add_header("Authorization", format!("Bearer {}", token))
            .json(&json!({
                "username": format!("role_update_target_{}", ts),
                "email": format!("role_update_target_{}@example.com", ts),
                "password": "ProvisionPass123!",
                "role_ids": [role_id.clone()]
            }))
            .await;
        provision_resp.assert_status_ok();

        let update_resp = server
            .put(&format!("/api/rbac/roles/{}", role_id))
            .add_header("Authorization", format!("Bearer {}", token))
            .json(&json!({
                "assignable_to": "service"
            }))
            .await;
        assert_eq!(update_resp.status_code(), axum::http::StatusCode::CONFLICT);
        let update_body: serde_json::Value = update_resp.json();
        assert_eq!(update_body["error"], "role_assignment_conflict");

        let get_role_resp = server
            .get(&format!("/api/rbac/roles/{}", role_id))
            .add_header("Authorization", format!("Bearer {}", token))
            .await;
        get_role_resp.assert_status_ok();
        let get_role_body: serde_json::Value = get_role_resp.json();
        assert_eq!(get_role_body["data"]["role"]["assignable_to"], "all");
    }

    #[tokio::test]
    async fn test_keylo_2_0_service_principal_authorization_flow() {
        let Some(server) = setup_test_server().await else {
            return;
        };
        let token = get_access_token(&server).await;
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();

        let service_id = format!("svc-2-0-{}", ts);
        let denied_service_id = format!("svc-2-0-denied-{}", ts);
        let service_secret = "ServiceSecret123!";
        let role_name = format!("crawler_service_{}", ts);
        let permission_name = format!("service:crawler:invoke:{}", ts);
        let resource_code = format!("crawler:invoke:{}", ts);

        let role_resp = server
            .post("/api/rbac/roles")
            .add_header("Authorization", format!("Bearer {}", token))
            .json(&json!({
                "name": role_name,
                "description": "Crawler service role",
                "assignable_to": "service"
            }))
            .await;
        role_resp.assert_status_ok();
        let role_body: serde_json::Value = role_resp.json();
        let role_id = role_body["data"]["id"].as_str().unwrap().to_string();

        let permission_resp = server
            .post("/api/rbac/permissions")
            .add_header("Authorization", format!("Bearer {}", token))
            .json(&json!({
                "name": permission_name,
                "description": "Invoke crawler service"
            }))
            .await;
        permission_resp.assert_status_ok();
        let permission_body: serde_json::Value = permission_resp.json();
        let permission_id = permission_body["data"]["id"].as_str().unwrap().to_string();

        let bind_permission_resp = server
            .post(&format!("/api/rbac/roles/{}/permissions", role_id))
            .add_header("Authorization", format!("Bearer {}", token))
            .json(&json!({ "permission_id": permission_id }))
            .await;
        bind_permission_resp.assert_status_ok();

        let wrong_audience_service_id = format!("svc-2-0-wrong-aud-{}", ts);
        for id in [&service_id, &denied_service_id] {
            let service_resp = server
                .post("/v1/admin/services")
                .add_header("Authorization", format!("Bearer {}", token))
                .json(&json!({
                    "service_id": id,
                    "service_secret": service_secret,
                    "name": id,
                    "allowed_scopes": ["read"],
                    "allowed_audiences": ["admin-backend"]
                }))
                .await;
            service_resp.assert_status_ok();
        }

        let wrong_audience_service_resp = server
            .post("/v1/admin/services")
            .add_header("Authorization", format!("Bearer {}", token))
            .json(&json!({
                "service_id": wrong_audience_service_id,
                "service_secret": service_secret,
                "name": wrong_audience_service_id,
                "allowed_scopes": ["read"],
                "allowed_audiences": ["inventory-svc"]
            }))
            .await;
        wrong_audience_service_resp.assert_status_ok();

        let principals_resp = server
            .get("/v1/admin/principals?principal_type=service")
            .add_header("Authorization", format!("Bearer {}", token))
            .await;
        principals_resp.assert_status_ok();
        let principals_body: serde_json::Value = principals_resp.json();
        let service_principal_id = principals_body["data"]
            .as_array()
            .unwrap()
            .iter()
            .find(|principal| principal["ref_id"] == service_id)
            .and_then(|principal| principal["id"].as_str())
            .unwrap()
            .to_string();

        let assign_role_resp = server
            .post(&format!(
                "/v1/admin/principals/{}/roles",
                service_principal_id
            ))
            .add_header("Authorization", format!("Bearer {}", token))
            .json(&json!({ "role_id": role_id }))
            .await;
        assign_role_resp.assert_status_ok();

        let effective_resp = server
            .get(&format!(
                "/v1/admin/principals/{}/effective-permissions",
                service_principal_id
            ))
            .add_header("Authorization", format!("Bearer {}", token))
            .await;
        effective_resp.assert_status_ok();
        let effective_body: serde_json::Value = effective_resp.json();
        assert!(effective_body["data"]["permissions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|permission| permission["name"] == permission_name));

        let resource_resp = server
            .post("/v1/admin/resources")
            .add_header("Authorization", format!("Bearer {}", token))
            .json(&json!({
                "app": "crawler",
                "resource_type": "service",
                "code": resource_code,
                "name": "Crawler invoke",
                "permission_ids": [permission_id]
            }))
            .await;
        resource_resp.assert_status_ok();

        let service_token_resp = server
            .post("/v1/service/token")
            .json(&json!({
                "service_id": service_id,
                "service_secret": service_secret,
                "audience": "admin-backend",
                "scope": "read"
            }))
            .await;
        service_token_resp.assert_status_ok();
        let service_token_body: serde_json::Value = service_token_resp.json();
        let service_token = service_token_body["access_token"].as_str().unwrap();

        let check_resp = server
            .post("/v1/authorize/check")
            .add_header("Authorization", format!("Bearer {}", service_token))
            .json(&json!({ "permission": permission_name }))
            .await;
        check_resp.assert_status_ok();
        let check_body: serde_json::Value = check_resp.json();
        assert_eq!(check_body["data"]["allowed"], true);

        let tree_resp = server
            .get("/v1/principals/me/resource-tree?app=crawler&type=service")
            .add_header("Authorization", format!("Bearer {}", service_token))
            .await;
        tree_resp.assert_status_ok();
        let tree_body: serde_json::Value = tree_resp.json();
        assert!(tree_body["data"]
            .as_array()
            .unwrap()
            .iter()
            .any(|node| node["resource"]["code"] == resource_code));

        let denied_token_resp = server
            .post("/v1/service/token")
            .json(&json!({
                "service_id": denied_service_id,
                "service_secret": service_secret,
                "audience": "admin-backend",
                "scope": "read"
            }))
            .await;
        denied_token_resp.assert_status_ok();
        let denied_token_body: serde_json::Value = denied_token_resp.json();
        let denied_token = denied_token_body["access_token"].as_str().unwrap();

        let denied_check_resp = server
            .post("/v1/authorize/check")
            .add_header("Authorization", format!("Bearer {}", denied_token))
            .json(&json!({ "permission": permission_name }))
            .await;
        denied_check_resp.assert_status_ok();
        let denied_check_body: serde_json::Value = denied_check_resp.json();
        assert_eq!(denied_check_body["data"]["allowed"], false);

        let wrong_audience_token_resp = server
            .post("/v1/service/token")
            .json(&json!({
                "service_id": wrong_audience_service_id,
                "service_secret": service_secret,
                "audience": "inventory-svc",
                "scope": "read"
            }))
            .await;
        wrong_audience_token_resp.assert_status_ok();
        let wrong_audience_token_body: serde_json::Value = wrong_audience_token_resp.json();
        let wrong_audience_token = wrong_audience_token_body["access_token"].as_str().unwrap();

        let wrong_audience_check_resp = server
            .post("/v1/authorize/check")
            .add_header("Authorization", format!("Bearer {}", wrong_audience_token))
            .json(&json!({ "permission": permission_name }))
            .await;
        assert_eq!(
            wrong_audience_check_resp.status_code(),
            axum::http::StatusCode::UNAUTHORIZED
        );
        let wrong_audience_check_body: serde_json::Value = wrong_audience_check_resp.json();
        assert_eq!(wrong_audience_check_body["error"], "invalid_audience");
    }

    #[tokio::test]
    async fn test_keylo_2_0_user_menu_resource_tree_flow() {
        let Some(server) = setup_test_server().await else {
            return;
        };
        let admin_token = get_access_token(&server).await;
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();

        let role_name = format!("keystone_operator_{}", ts);
        let permission_name = format!("keystone:system:user:list:{}", ts);
        let username = format!("keystone_user_{}", ts);
        let email = format!("keystone_user_{}@example.com", ts);
        let password = "KeystoneUser123!";
        let resource_code = format!("system:user:{}", ts);

        let role_resp = server
            .post("/api/rbac/roles")
            .add_header("Authorization", format!("Bearer {}", admin_token))
            .json(&json!({
                "name": role_name,
                "description": "Keystone operator",
                "assignable_to": "user"
            }))
            .await;
        role_resp.assert_status_ok();
        let role_body: serde_json::Value = role_resp.json();
        let role_id = role_body["data"]["id"].as_str().unwrap().to_string();

        let permission_resp = server
            .post("/api/rbac/permissions")
            .add_header("Authorization", format!("Bearer {}", admin_token))
            .json(&json!({
                "name": permission_name,
                "description": "Keystone user list"
            }))
            .await;
        permission_resp.assert_status_ok();
        let permission_body: serde_json::Value = permission_resp.json();
        let permission_id = permission_body["data"]["id"].as_str().unwrap().to_string();

        let bind_permission_resp = server
            .post(&format!("/api/rbac/roles/{}/permissions", role_id))
            .add_header("Authorization", format!("Bearer {}", admin_token))
            .json(&json!({ "permission_id": permission_id }))
            .await;
        bind_permission_resp.assert_status_ok();

        let provision_resp = server
            .post("/v1/admin/users/provision")
            .add_header("Authorization", format!("Bearer {}", admin_token))
            .json(&json!({
                "username": username,
                "email": email,
                "password": password,
                "role_ids": [role_id]
            }))
            .await;
        provision_resp.assert_status_ok();

        let resource_resp = server
            .post("/v1/admin/resources")
            .add_header("Authorization", format!("Bearer {}", admin_token))
            .json(&json!({
                "app": "keystone",
                "resource_type": "menu",
                "code": resource_code,
                "name": "用户管理",
                "metadata": {
                    "router_name": "SystemUser",
                    "path": "/system/user",
                    "component": "system/user/index",
                    "meta": {
                        "title": "用户管理",
                        "icon": "user",
                        "showLink": true
                    }
                },
                "permission_ids": [permission_id]
            }))
            .await;
        resource_resp.assert_status_ok();

        let login_resp = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": username,
                "client_secret": password
            }))
            .await;
        login_resp.assert_status_ok();
        let login_body: serde_json::Value = login_resp.json();
        let user_token = login_body["access_token"].as_str().unwrap();
        assert!(login_body["refresh_token"].as_str().is_some());

        let check_resp = server
            .post("/v1/authorize/check")
            .add_header("Authorization", format!("Bearer {}", user_token))
            .json(&json!({ "permission": permission_name }))
            .await;
        check_resp.assert_status_ok();
        let check_body: serde_json::Value = check_resp.json();
        assert_eq!(check_body["data"]["allowed"], true);

        let tree_resp = server
            .get("/v1/principals/me/resource-tree?app=keystone&type=menu")
            .add_header("Authorization", format!("Bearer {}", user_token))
            .await;
        tree_resp.assert_status_ok();
        let tree_body: serde_json::Value = tree_resp.json();
        let user_menu_node = tree_body["data"]
            .as_array()
            .unwrap()
            .iter()
            .find(|node| node["resource"]["code"] == resource_code)
            .unwrap();
        assert_eq!(
            user_menu_node["resource"]["metadata"]["path"],
            "/system/user"
        );
        assert_eq!(
            user_menu_node["resource"]["metadata"]["meta"]["title"],
            "用户管理"
        );
    }

    #[tokio::test]
    async fn test_keystone_wildcard_permission_allows_any_rbac_check_and_resource_tree() {
        let Some(server) = setup_test_server().await else {
            return;
        };
        let admin_token = get_access_token(&server).await;
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();

        let role_name = format!("keystone_super_admin_{}", ts);
        let username = format!("keystone_root_{}", ts);
        let email = format!("keystone_root_{}@example.com", ts);
        let password = "KeystoneRoot123!";
        let resource_code = format!("system:audit:{}", ts);
        let arbitrary_permission = format!("keystone:system:audit:export:{}", ts);

        let role_resp = server
            .post("/api/rbac/roles")
            .add_header("Authorization", format!("Bearer {}", admin_token))
            .json(&json!({
                "name": role_name,
                "description": "Keystone wildcard admin",
                "assignable_to": "user"
            }))
            .await;
        role_resp.assert_status_ok();
        let role_body: serde_json::Value = role_resp.json();
        let role_id = role_body["data"]["id"].as_str().unwrap().to_string();

        let wildcard_permission_id =
            get_or_create_permission_id(&server, &admin_token, "*:*:*", "Keystone wildcard").await;

        let bind_permission_resp = server
            .post(&format!("/api/rbac/roles/{}/permissions", role_id))
            .add_header("Authorization", format!("Bearer {}", admin_token))
            .json(&json!({ "permission_id": wildcard_permission_id }))
            .await;
        bind_permission_resp.assert_status_ok();

        let provision_resp = server
            .post("/v1/admin/users/provision")
            .add_header("Authorization", format!("Bearer {}", admin_token))
            .json(&json!({
                "username": username,
                "email": email,
                "password": password,
                "role_ids": [role_id]
            }))
            .await;
        provision_resp.assert_status_ok();

        let resource_resp = server
            .post("/v1/admin/resources")
            .add_header("Authorization", format!("Bearer {}", admin_token))
            .json(&json!({
                "app": "keystone",
                "resource_type": "menu",
                "code": resource_code,
                "name": "审计导出",
                "display_order": 99
            }))
            .await;
        resource_resp.assert_status_ok();

        let login_resp = server
            .post("/v1/auth/token")
            .json(&json!({
                "client_id": username,
                "client_secret": password
            }))
            .await;
        login_resp.assert_status_ok();
        let login_body: serde_json::Value = login_resp.json();
        let user_token = login_body["access_token"].as_str().unwrap();

        let check_resp = server
            .post("/v1/authorize/check")
            .add_header("Authorization", format!("Bearer {}", user_token))
            .json(&json!({ "permission": arbitrary_permission }))
            .await;
        check_resp.assert_status_ok();
        let check_body: serde_json::Value = check_resp.json();
        assert_eq!(check_body["data"]["allowed"], true);

        let tree_resp = server
            .get("/v1/principals/me/resource-tree?app=keystone&type=menu")
            .add_header("Authorization", format!("Bearer {}", user_token))
            .await;
        tree_resp.assert_status_ok();
        let tree_body: serde_json::Value = tree_resp.json();
        assert!(tree_body["data"]
            .as_array()
            .unwrap()
            .iter()
            .any(|node| node["resource"]["code"] == resource_code));
    }
}
