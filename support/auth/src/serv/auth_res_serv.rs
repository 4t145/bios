use std::{collections::HashMap, sync::RwLock};

use lazy_static::lazy_static;
use tardis::{
    basic::{error::TardisError, result::TardisResult},
    futures::executor::block_on,
    log::info,
    serde_json::Value,
    url::Url,
    TardisFuns,
};

use crate::helper::auth_common_helper;
use crate::{
    auth_config::AuthConfig,
    auth_constants::DOMAIN_CODE,
    dto::auth_kernel_dto::{Api, ResAuthInfo, ResContainerLeafInfo, ResContainerNode, ServConfig},
};

use super::auth_crypto_serv;

//todo Change to asynchronous lock or spin when obtaining lock/改成异步锁或者是获取锁的时候自旋
lazy_static! {
    static ref RES_CONTAINER: RwLock<Option<ResContainerNode>> = RwLock::new(None);
    static ref RES_APIS: RwLock<Option<HashMap<String, Api>>> = RwLock::new(None);
}

pub fn get_res_json() -> TardisResult<Value> {
    if let Ok(res) = RES_CONTAINER.read() {
        if let Some(res) = res.as_ref() {
            return TardisFuns::json.obj_to_json(res);
        }
    }
    Ok(Value::Null)
}

pub fn get_apis_json() -> TardisResult<Value> {
    let config = TardisFuns::cs_config::<AuthConfig>(DOMAIN_CODE);
    let apis = if let Ok(apis) = RES_APIS.read() {
        if let Some(apis) = apis.as_ref() {
            apis.clone()
        } else {
            HashMap::new()
        }
    } else {
        HashMap::new()
    };
    let pub_key = block_on(auth_crypto_serv::fetch_public_key())?;
    TardisFuns::json.obj_to_json(&ServConfig {
        strict_security_mode: config.strict_security_mode,
        double_auth_exp_sec: config.double_auth_exp_sec,
        pub_key,
        apis: apis.into_values().collect(),
        login_req_method: config.extra_api.login_req_method.clone(),
        login_req_paths: config.extra_api.login_req_paths.clone(),
        logout_req_method: config.extra_api.logout_req_method.clone(),
        logout_req_path: config.extra_api.logout_req_path.clone(),
        double_auth_req_method: config.extra_api.double_auth_req_method.clone(),
        double_auth_req_path: config.extra_api.double_auth_req_path.clone(),
    })
}

fn parse_uri(res_uri: &str) -> TardisResult<Vec<String>> {
    let res_uri = Url::parse(res_uri).map_err(|_| TardisError::format_error(&format!("[Auth] Invalid url {res_uri}"), ""))?;
    let mut uri_items = vec![];
    uri_items.push(res_uri.scheme().to_lowercase());
    if let Some(host) = res_uri.host_str() {
        if let Some(port) = res_uri.port() {
            uri_items.push(format!("{host}:{port}"));
        } else {
            uri_items.push(host.to_string());
        }
    } else {
        uri_items.push("".to_string());
    }
    let path = res_uri.path();
    if !path.is_empty() && path != "/" {
        let paths = if let Some(path) = res_uri.path().strip_prefix('/') { path } else { res_uri.path() }.split('/').map(|i| i.to_lowercase()).collect::<Vec<String>>();
        uri_items.extend(paths);
    }
    if let Some(query) = res_uri.query() {
        uri_items.push("?".to_string());
        uri_items.push(auth_common_helper::sort_query(query));
    }
    uri_items.push("$".to_string());
    Ok(uri_items)
}

pub fn init_res() -> TardisResult<()> {
    let mut res_container = RES_CONTAINER.write()?;
    let mut res_apis = RES_APIS.write()?;
    if res_container.is_none() {
        *res_container = Some(ResContainerNode::new());
    }
    if res_apis.is_none() {
        *res_apis = Some(HashMap::new());
    }
    Ok(())
}

/// # add resource
/// **attention!!**: Before calling this method, init_res() must be called first
pub fn add_res(
    res_action: &str,
    res_uri: &str,
    auth_info: Option<ResAuthInfo>,
    need_crypto_req: bool,
    need_crypto_resp: bool,
    need_double_auth: bool,
    need_login: bool,
) -> TardisResult<()> {
    let res_action = res_action.to_lowercase();
    info!("[Auth] Add resource [{}][{}]", res_action, res_uri);
    let res_items = parse_uri(res_uri)?;
    let mut res_container = RES_CONTAINER.write()?;
    let mut res_apis = RES_APIS.write()?;
    if res_container.is_none() {
        *res_container = Some(ResContainerNode::new());
    }
    if res_apis.is_none() {
        *res_apis = Some(HashMap::new());
    }
    let mut res_container_node = res_container.as_mut().expect("[Auth] res_container got none");
    for res_item in res_items.into_iter() {
        if !res_container_node.has_child(&res_item) {
            res_container_node.insert_child(&res_item);
        }
        res_container_node = res_container_node.get_child_mut(&res_item);
        if res_item == "$" {
            res_container_node.insert_leaf(
                &res_action,
                &res_action,
                res_uri,
                auth_info.clone(),
                need_crypto_req,
                need_crypto_resp,
                need_double_auth,
                need_login,
            );
            let res_uris: Vec<&str> = res_uri.split("://").collect();
            if res_uris.len() == 2 {
                res_apis.as_mut().expect("[Auth] res_apis got none").insert(
                    format!("{res_uri}##{res_action}"),
                    Api {
                        action: res_action.clone(),
                        uri: res_uris[1].to_string(),
                        need_crypto_req,
                        need_crypto_resp,
                        need_double_auth,
                        need_login,
                    },
                );
            }
        }
    }
    Ok(())
}

fn remove_empty_node(res_container_node: &mut ResContainerNode, mut res_items: Vec<String>) {
    if res_container_node.child_len() == 0 || res_items.is_empty() {
        return;
    }
    let res_item = res_items.remove(0);
    remove_empty_node(res_container_node.get_child_mut(&res_item), res_items);
    if res_container_node.get_child(&res_item).child_len() == 0 {
        res_container_node.remove_child(&res_item);
    }
}

pub fn remove_res(res_action: &str, res_uri: &str) -> TardisResult<()> {
    let res_action = res_action.to_lowercase();
    info!("[Auth] Remove resource [{}][{}]", res_action, res_uri);
    let res_items = parse_uri(res_uri)?;
    let mut res_container = RES_CONTAINER.write()?;
    let mut res_container_node = res_container.as_mut().expect("[Auth] res_container got none");
    let mut res_apis = RES_APIS.write()?;
    let apis = res_apis.as_mut().expect("[Auth] res_apis got none");
    for res_item in res_items.iter() {
        if !res_container_node.has_child(res_item) {
            return Ok(());
        }
        res_container_node = res_container_node.get_child_mut(res_item);
    }
    apis.remove(&format!("{res_uri}##{res_action}"));
    res_container_node.remove_child(&res_action);
    remove_empty_node(res_container.as_mut().expect("[Auth] res_container got none"), res_items);
    Ok(())
}

pub async fn delete_auth(res_action: &str, res_uri: &str) -> TardisResult<()> {
    TardisFuns::cache_by_module_or_default(DOMAIN_CODE)
        .hdel(
            &TardisFuns::cs_config::<AuthConfig>(DOMAIN_CODE).cache_key_res_info,
            &format!("{}##{}", res_uri, res_action),
        )
        .await
        .map_err(|e| TardisError::internal_error(&format!("[Auth] delete_auth failed: {}", e), ""))?;
    remove_res(res_action, res_uri)
}

fn do_match_res(res_action: &str, res_container: &ResContainerNode, res_items: &Vec<String>, multi_wildcard: bool, matched_uris: &mut Vec<ResContainerLeafInfo>) {
    // TODO "res_items[0] == "?"" approach will ignore the query, there needs to be a better way
    if res_container.has_child("$") && (res_items.is_empty() || multi_wildcard || res_items[0] == "?") {
        // matched
        if let Some(leaf_node) = res_container.get_child("$").get_child_opt(res_action) {
            matched_uris.push(leaf_node.get_leaf_info());
        }
        if let Some(leaf_node) = res_container.get_child("$").get_child_opt("*") {
            matched_uris.push(leaf_node.get_leaf_info());
        }
        return;
    }
    if res_items.is_empty() {
        // un-matched
        return;
    }
    let curr_items = &res_items[0];
    let next_items = &res_items[1..].to_vec();
    if let Some(next_res_container) = res_container.get_child_opt(curr_items) {
        do_match_res(res_action, next_res_container, next_items, false, matched_uris);
    }
    if let Some(next_res_container) = res_container.get_child_opt("*") {
        do_match_res(res_action, next_res_container, next_items, false, matched_uris);
    }
    if let Some(next_res_container) = res_container.get_child_opt("**") {
        do_match_res(res_action, next_res_container, next_items, true, matched_uris);
    }
    if multi_wildcard {
        do_match_res(res_action, res_container, next_items, true, matched_uris);
    }
}

pub fn match_res(res_action: &str, res_uri: &str) -> TardisResult<Vec<ResContainerLeafInfo>> {
    let res_action = res_action.to_lowercase();
    let mut res_items = parse_uri(res_uri)?;
    // remove $ node;
    res_items.remove(res_items.len() - 1);
    let mut matched_uris = vec![];
    let res_container = RES_CONTAINER.read()?;
    do_match_res(
        &res_action,
        res_container.as_ref().expect("[Auth] res_container got none"),
        &res_items,
        false,
        &mut matched_uris,
    );
    Ok(matched_uris)
}
