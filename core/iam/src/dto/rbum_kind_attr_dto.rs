use serde::{Deserialize, Serialize};
use tardis::chrono::{DateTime, Utc};
use tardis::db::sea_orm::*;
use tardis::web::Object;

#[derive(Object, Serialize, Deserialize, Debug)]
pub struct RbumKindAttrAddReq {
    #[oai(validator(min_length = "2", max_length = "255"))]
    pub code: String,
    #[oai(validator(min_length = "2", max_length = "255"))]
    pub name: String,
    #[oai(validator(max_length = "2000"))]
    pub note: String,
    #[oai(validator(max_length = "1000"))]
    pub icon: String,
    pub sort: i32,

    pub main_column: bool,
    pub position: bool,
    pub capacity: bool,
    pub overload: bool,
    #[oai(validator(max_length = "255"))]
    pub data_type_kind: String,
    #[oai(validator(max_length = "255"))]
    pub widget_type: String,
    #[oai(validator(max_length = "2000"))]
    pub default_value: String,
    #[oai(validator(max_length = "255"))]
    pub options: String,
    pub required: bool,
    pub min_length: i8,
    pub max_length: i8,
    #[oai(validator(max_length = "2000"))]
    pub action: String,
    #[oai(validator(max_length = "255"))]
    pub rel_rbum_kind_id: String,
}

#[derive(Object, Serialize, Deserialize, Debug)]
pub struct RbumKindAttrModifyReq {
    #[oai(validator(min_length = "2", max_length = "255"))]
    pub name: Option<String>,
    #[oai(validator(max_length = "2000"))]
    pub note: Option<String>,
    #[oai(validator(max_length = "1000"))]
    pub icon: Option<String>,
    pub sort: Option<i32>,
    #[oai(validator(max_length = "255"))]
    pub scope_kind: Option<String>,

    pub main_column: Option<bool>,
    pub position: Option<bool>,
    pub capacity: Option<bool>,
    pub overload: Option<bool>,
    #[oai(validator(max_length = "255"))]
    pub data_type_kind: Option<String>,
    #[oai(validator(max_length = "255"))]
    pub widget_type: Option<String>,
    #[oai(validator(max_length = "2000"))]
    pub default_value: Option<String>,
    #[oai(validator(max_length = "255"))]
    pub options: Option<String>,
    pub required: Option<bool>,
    pub min_length: Option<i8>,
    pub max_length: Option<i8>,
    #[oai(validator(max_length = "2000"))]
    pub action: Option<String>,
}

#[derive(Object, FromQueryResult, Serialize, Deserialize, Debug)]
pub struct RbumKindAttrSummaryResp {
    id: String,
    pub code: String,
    pub name: String,
    pub icon: String,
    pub sort: i32,

    pub main_column: bool,
    pub position: bool,
    pub capacity: bool,
    pub overload: bool,
}

#[derive(Object, FromQueryResult, Serialize, Deserialize, Debug)]
pub struct RbumKindAttrDetailResp {
    pub id: String,
    pub rel_app_name: String,
    pub rel_tenant_name: String,
    pub creator_name: String,
    pub updater_name: String,
    pub create_time: DateTime<Utc>,
    pub update_time: DateTime<Utc>,
    pub code: String,
    pub name: String,
    pub note: String,
    pub icon: String,
    pub sort: i32,

    pub scope_kind: String,

    pub main_column: bool,
    pub position: bool,
    pub capacity: bool,
    pub overload: bool,
    pub data_type_kind: String,
    pub widget_type: String,
    pub default_value: String,
    pub options: String,
    pub required: bool,
    pub min_length: i8,
    pub max_length: i8,
    pub action: String,
    pub rel_rbum_kind_name: String,
}
