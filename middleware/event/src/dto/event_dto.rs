use bios_basic::rbum::dto::rbum_filer_dto::{RbumBasicFilterReq, RbumItemFilterFetcher};
use serde::{Deserialize, Serialize};
use tardis::{
    basic::field::TrimString,
    db::sea_orm::{self},
    serde_json::Value,
    web::poem_openapi,
};

#[derive(poem_openapi::Object, Serialize, Deserialize, Debug)]
pub struct EventTopicAddOrModifyReq {
    #[oai(validator(pattern = r"^[a-z0-9]+$"))]
    pub code: TrimString,
    pub name: TrimString,
    pub save_message: bool,
    pub need_mgr: bool,
    #[oai(validator(minimum(value = "1", exclusive = "false")))]
    pub queue_size: i32,
    pub use_sk: Option<String>,
    pub mgr_sk: Option<String>,
}

#[derive(poem_openapi::Object, sea_orm::FromQueryResult, Serialize, Deserialize, Debug)]
pub struct EventTopicInfoResp {
    #[oai(validator(pattern = r"^[a-z0-9]+$"))]
    pub code: String,
    pub name: String,
    pub save_message: bool,
    pub need_mgr: bool,
    #[oai(validator(minimum(value = "1", exclusive = "false")))]
    pub queue_size: i32,
    pub use_sk: String,
    pub mgr_sk: String,
}

#[derive(poem_openapi::Object, Serialize, Deserialize, Debug, Clone, Default)]
#[serde(default)]
pub struct EventTopicFilterReq {
    pub basic: RbumBasicFilterReq,
}

impl RbumItemFilterFetcher for EventTopicFilterReq {
    fn basic(&self) -> &RbumBasicFilterReq {
        &self.basic
    }

    fn rel(&self) -> &Option<bios_basic::rbum::dto::rbum_filer_dto::RbumItemRelFilterReq> {
        &None
    }

    fn rel2(&self) -> &Option<bios_basic::rbum::dto::rbum_filer_dto::RbumItemRelFilterReq> {
        &None
    }
}

#[derive(poem_openapi::Object, Serialize, Deserialize, Debug)]
pub struct EventListenerRegisterReq {
    #[oai(validator(pattern = r"^[a-z0-9]+$"))]
    pub topic_code: TrimString,
    pub topic_sk: Option<String>,
    #[oai(validator(pattern = r"^[a-z0-9-_]+$"))]
    pub events: Option<Vec<TrimString>>,
    pub avatars: Vec<TrimString>,
    pub subscribe_mode: bool,
}
#[derive(poem_openapi::Object, Serialize, Deserialize, Debug)]
pub struct EventListenerRegisterResp {
    pub ws_addr: String,
    pub listener_code: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EventListenerInfo {
    pub topic_code: String,
    pub subscribe_mode: bool,
    pub events: Option<Vec<String>>,
    pub avatars: Vec<String>,
    pub mgr: bool,
    pub token: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EventMessageMgrWrap {
    pub msg: Value,
    pub ori_from_avatar: String,
    pub ori_to_avatars: Option<Vec<String>>,
}
