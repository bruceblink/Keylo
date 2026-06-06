use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Resource {
    pub id: String,
    pub app: String,
    pub resource_type: String,
    pub code: String,
    pub name: String,
    pub parent_id: Option<String>,
    pub display_order: i32,
    pub description: Option<String>,
    pub active: bool,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

#[derive(Debug, Deserialize)]
pub struct CreateResourceRequest {
    pub app: String,
    pub resource_type: String,
    pub code: String,
    pub name: String,
    pub parent_id: Option<String>,
    pub display_order: Option<i32>,
    pub description: Option<String>,
    pub permission_ids: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct ResourceListQuery {
    pub app: Option<String>,
    #[serde(rename = "type")]
    pub resource_type: Option<String>,
    pub active: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct ResourceTreeQuery {
    pub app: String,
    #[serde(rename = "type")]
    pub resource_type: String,
}

#[derive(Debug, Deserialize)]
pub struct AssignResourcePermissionRequest {
    pub permission_id: String,
}

#[derive(Debug, Serialize)]
pub struct ResourceTreeNode {
    pub resource: Resource,
    pub permissions: Vec<crate::models::Permission>,
    pub children: Vec<ResourceTreeNode>,
}
