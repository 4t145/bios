use std::time::*;

use serde::{Deserialize, Serialize};

use tardis::web::poem_openapi;
use tardis::web::poem_openapi::types::*;

use crate::utils::parse_tags;

use super::conf_config_dto::{ConfigDescriptor, ConfigPublishRequest};
use super::conf_namespace_dto::{NamespaceAttribute, NamespaceId, NamespaceItem};
#[derive(Debug, Serialize, Deserialize, poem_openapi::Object)]
pub struct NacosResponse<T: Type + ParseFromJSON + ToJSON> {
    code: u16,
    message: Option<String>,
    data: T,
}

impl<T: Type + ParseFromJSON + ToJSON> NacosResponse<T> {
    pub const fn ok(data: T) -> Self {
        Self { code: 200, message: None, data }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NacosJwtClaim {
    pub exp: u64,
    pub sub: String,
}

impl NacosJwtClaim {
    pub fn gen(ttl: u64, user: &str) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("invalid system time cause by time travel").as_secs();
        Self {
            exp: now + ttl,
            sub: String::from(user),
        }
    }
}

#[derive(poem_openapi::Object, Serialize, Deserialize, Debug, Default)]
#[serde(rename = "camelCase")]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(poem_openapi::Object, Serialize, Deserialize, Debug, Default)]
#[serde(rename = "camelCase")]
pub struct LoginResponse {
    #[oai(rename = "accessToken")]
    pub access_token: String,
    #[oai(rename = "tokenTtl")]
    pub token_ttl: u32,
    #[oai(rename = "globalAdmin")]
    pub global_admin: bool,
}

#[derive(poem_openapi::Object, Serialize, Deserialize, Debug, Default)]
pub struct PublishConfigForm {
    pub content: String,
}

#[derive(poem_openapi::Object, Serialize, Deserialize, Debug, Default)]
#[allow(non_snake_case)]
pub struct PublishConfigFormV2 {
    //否 命名空间，默认为public与 ''相同
    pub namespaceId: Option<String>,
    #[oai(validator(min_length = 1, max_length = 256))]
    //是 配置组名
    pub group: String,
    #[oai(validator(min_length = 1, max_length = 256))]
    //是 配置名
    pub dataId: String,
    //是 配置内容
    pub content: String,
    //否 标签
    pub tag: Option<String>,
    //否 应用名
    pub appName: Option<String>,
    //否 源用户
    pub srcUser: Option<String>,
    //否 配置标签列表，可多个，逗号分隔
    pub configTags: Option<String>,
    //否 配置描述
    pub desc: Option<String>,
    //否 -
    pub r#use: Option<String>,
    //否 -
    pub effect: Option<String>,
    //否 配置类型
    pub r#type: Option<String>,
    //否 -
    pub schema: Option<String>,
}

impl From<PublishConfigFormV2> for ConfigPublishRequest {
    fn from(val: PublishConfigFormV2) -> Self {
        let config_tags = val.configTags.as_deref().map(parse_tags).unwrap_or_default();
        ConfigPublishRequest {
            content: val.content,
            descriptor: ConfigDescriptor {
                namespace_id: val.namespaceId.unwrap_or("public".into()),
                group: val.group,
                data_id: val.dataId,
                tags: val.tag.into_iter().collect(),
                tp: val.r#type,
            },
            app_name: val.appName,
            src_user: val.srcUser,
            config_tags,
            desc: val.desc,
            r#use: val.r#use,
            effect: val.effect,
            schema: val.schema,
        }
    }
}
#[derive(poem_openapi::Object, Serialize, Deserialize, Debug, Default)]
#[allow(non_snake_case)]
pub struct NacosCreateNamespaceRequest {
    customNamespaceId: String,
    namespaceName: String,
    namespaceDesc: Option<String>,
}

#[derive(poem_openapi::Object, Serialize, Deserialize, Debug, Default)]
#[allow(non_snake_case)]
pub struct NacosEditNamespaceRequest {
    namespace: String,
    namespaceShowName: String,
    namespaceDesc: Option<String>,
}

#[derive(poem_openapi::Object, Serialize, Deserialize, Debug, Default)]
#[allow(non_snake_case)]
pub struct NacosDeleteNamespaceRequest {
    pub(crate) namespaceId: String,
}

impl From<NacosCreateNamespaceRequest> for NamespaceAttribute {
    fn from(value: NacosCreateNamespaceRequest) -> Self {
        Self {
            namespace: value.customNamespaceId,
            namespace_show_name: value.namespaceName,
            namespace_desc: value.namespaceDesc,
        }
    }
}

impl From<NacosEditNamespaceRequest> for NamespaceAttribute {
    fn from(value: NacosEditNamespaceRequest) -> Self {
        Self {
            namespace: value.namespace,
            namespace_show_name: value.namespaceShowName,
            namespace_desc: value.namespaceDesc,
        }
    }
}

#[derive(poem_openapi::Object, Serialize, Deserialize, Debug, Default)]
#[allow(non_snake_case)]
pub struct NamespaceItemNacos {
    pub namespace: NamespaceId,
    pub namespaceShowName: String,
    pub namespaceDesc: Option<String>,
    pub r#type: u32,
    /// quota / 容量,
    /// refer to design of nacos,
    /// see: https://github.com/alibaba/nacos/issues/4558
    pub quota: u32,
    pub configCount: u32,
}

impl From<NamespaceItem> for NamespaceItemNacos {
    fn from(value: NamespaceItem) -> Self {
        Self {
            namespace: value.namespace,
            namespaceShowName: value.namespace_show_name,
            namespaceDesc: value.namespace_desc,
            r#type: value.tp,
            quota: value.quota,
            configCount: value.config_count,
        }
    }
}
