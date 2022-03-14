use serde::{Deserialize, Serialize};
use tardis::chrono::{DateTime, Utc};
use tardis::web::poem_openapi::Object;

use crate::rbum::enumeration::RbumScopeKind;

#[derive(Object, Serialize, Deserialize, Debug)]
pub struct RbumSetCateAddReq {
    #[oai(validator(min_length = "2", max_length = "255"))]
    pub bus_code: String,
    #[oai(validator(min_length = "2", max_length = "255"))]
    pub name: String,
    pub sort: Option<i32>,

    pub scope_kind: Option<RbumScopeKind>,
}

#[derive(Object, Serialize, Deserialize, Debug)]
pub struct RbumSetCateModifyReq {
    #[oai(validator(min_length = "2", max_length = "255"))]
    pub bus_code: Option<String>,
    #[oai(validator(min_length = "2", max_length = "255"))]
    pub name: Option<String>,
    pub sort: Option<i32>,

    pub scope_kind: Option<RbumScopeKind>,
}

#[derive(Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "default", derive(tardis::web::poem_openapi::Object, tardis::db::sea_orm::FromQueryResult))]
pub struct RbumSetCateSummaryResp {
    pub id: String,
    pub bus_code: String,
    pub name: String,
    pub sort: i32,

    pub create_time: DateTime<Utc>,
    pub update_time: DateTime<Utc>,

    pub scope_kind: RbumScopeKind,
}

#[derive(Serialize, Deserialize, Debug)]
#[cfg_attr(feature = "default", derive(tardis::web::poem_openapi::Object, tardis::db::sea_orm::FromQueryResult))]
pub struct RbumSetCateDetailResp {
    pub id: String,
    pub bus_code: String,
    pub name: String,
    pub sort: i32,

    pub rel_app_id: String,
    pub rel_app_name: String,
    pub rel_tenant_id: String,
    pub rel_tenant_name: String,
    pub updater_id: String,
    pub updater_name: String,
    pub create_time: DateTime<Utc>,
    pub update_time: DateTime<Utc>,

    pub scope_kind: RbumScopeKind,
}
