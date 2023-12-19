use std::collections::HashMap;

use std::str::FromStr;

use async_trait::async_trait;

use bios_sdk_invoke::invoke_config::InvokeConfig;
use bios_sdk_invoke::invoke_enumeration::InvokeModuleKind;
use bios_sdk_invoke::invoke_initializer;

use jsonpath_rust::JsonPathInst;
use serde::{Deserialize, Serialize};
use spacegate_kernel::def_filter;
use spacegate_kernel::plugins::context::SGRoleInfo;
use spacegate_kernel::plugins::{
    context::SgRoutePluginContext,
    filters::{SgPluginFilter, SgPluginFilterAccept, SgPluginFilterInitDto},
};
use tardis::serde_json::Value;

use tardis::basic::error::TardisError;
use tardis::{
    async_trait,
    basic::result::TardisResult,
    log,
    serde_json::{self},
    TardisFuns, TardisFunsInst,
};

use super::plugin_constants;

pub mod log_backend;

def_filter!("audit_log", SgFilterAuditLogDef, SgFilterAuditLog);

#[derive(Serialize, Deserialize)]
#[serde(default)]
pub struct SgFilterAuditLog {
    #[serde(flatten)]
    backend: log_backend::LogBackendEnum,
    header_token_name: String,
    success_json_path: String,
    success_json_path_values: Vec<String>,
    /// Exclude log path exact match.
    exclude_log_path: Vec<String>,
    enabled: bool,
    #[serde(skip)]
    jsonpath_inst: Option<JsonPathInst>,
}
impl SgFilterAuditLog {
    async fn get_log_content(&self, end_time: i64, ctx: &mut SgRoutePluginContext) -> TardisResult<LogParamContent> {
        let start_time = ctx.get_ext(&get_start_time_ext_code()).and_then(|time| time.parse::<i64>().ok());
        let body_string = if let Some(raw_body) = ctx.get_ext(plugin_constants::BEFORE_ENCRYPT_BODY) {
            serde_json::from_str::<Value>(raw_body)
        } else {
            let body = ctx.response.dump_body().await?;
            serde_json::from_slice::<Value>(&body)
        };
        let success = body_string
            .ok()
            .and_then(|json| {
                self.jsonpath_inst.as_ref().and_then(|inst| inst.find_slice(&json).into_iter().next()).map(|matched| {
                    if matched.is_string() {
                        matched.as_str().map(|matched| self.success_json_path_values.iter().any(|v| v == matched))
                    } else if matched.is_number() {
                        matched.as_i64().map(|matched| self.success_json_path_values.iter().filter_map(|v| v.parse::<i64>().ok()).any(|v| v == matched))
                    } else {
                        None
                    }
                })
            })
            .flatten()
            .unwrap_or(false);
        Ok(LogParamContent {
            op: ctx.request.get_method().to_string(),
            key: None,
            name: ctx.get_cert_info().and_then(|info| info.name.clone()).unwrap_or_default(),
            user_id: ctx.get_cert_info().map(|info| info.id.clone()),
            role: ctx.get_cert_info().map(|info| info.roles.clone()).unwrap_or_default(),
            ip: if let Some(real_ips) = ctx.request.get_headers().get("X-Forwarded-For") {
                real_ips.to_str().ok().and_then(|ips| ips.split(',').collect::<Vec<_>>().first().map(|ip| ip.to_string())).unwrap_or(ctx.request.get_remote_addr().ip().to_string())
            } else {
                ctx.request.get_remote_addr().ip().to_string()
            },
            path: ctx.request.get_uri_raw().path().to_string(),
            scheme: ctx.request.get_uri_raw().scheme_str().unwrap_or("http").to_string(),
            token: ctx.request.get_headers().get(&self.header_token_name).and_then(|v| v.to_str().ok().map(|v| v.to_string())),
            server_timing: start_time.map(|st| end_time - st),
            resp_status: ctx.response.get_status_code().as_u16().to_string(),
            success,
        })
    }
}

impl Default for SgFilterAuditLog {
    fn default() -> Self {
        Self {
            backend: Default::default(),
            header_token_name: "Bios-Token".to_string(),
            success_json_path: "$.code".to_string(),
            enabled: false,
            success_json_path_values: vec!["200".to_string(), "201".to_string()],
            exclude_log_path: vec!["/starsysApi/apis".to_string()],
            jsonpath_inst: None,
        }
    }
}

#[async_trait]
impl SgPluginFilter for SgFilterAuditLog {
    fn accept(&self) -> SgPluginFilterAccept {
        SgPluginFilterAccept {
            accept_error_response: true,
            ..Default::default()
        }
    }

    async fn init(&mut self, _: &SgPluginFilterInitDto) -> TardisResult<()> {
        self.enabled = true;
        if let Ok(jsonpath_inst) = JsonPathInst::from_str(&self.success_json_path).map_err(|e| log::error!("[Plugin.AuditLog] invalid json path:{e}")) {
            self.jsonpath_inst = Some(jsonpath_inst);
        } else {
            self.enabled = false;
        };
        match self.backend {
            log_backend::LogBackendEnum::Spi(ref mut spi) => {
                if !spi.log_url.is_empty() && !spi.spi_app_id.is_empty() {
                    invoke_initializer::init(
                        CODE,
                        InvokeConfig {
                            spi_app_id: spi.spi_app_id.clone(),
                            module_urls: HashMap::from([(InvokeModuleKind::Log.to_string(), spi.log_url.clone())]),
                        },
                    )?;
                    Ok(())
                } else {
                    self.enabled = false;
                    Err(TardisError::bad_request("[Plugin.AuditLog] plugin is not active, miss log_url or spi_app_id.", ""))
                }
            }
            log_backend::LogBackendEnum::Tracing(_) => Ok(()),
        }
    }

    async fn destroy(&self) -> TardisResult<()> {
        Ok(())
    }

    async fn req_filter(&self, _: &str, mut ctx: SgRoutePluginContext) -> TardisResult<(bool, SgRoutePluginContext)> {
        ctx.set_ext(&get_start_time_ext_code(), &tardis::chrono::Utc::now().timestamp_millis().to_string());
        return Ok((true, ctx));
    }

    async fn resp_filter(&self, _: &str, mut ctx: SgRoutePluginContext) -> TardisResult<(bool, SgRoutePluginContext)> {
        if self.enabled {
            let path = ctx.request.get_uri_raw().path().to_string();
            for exclude_path in self.exclude_log_path.clone() {
                if exclude_path == path {
                    return Ok((true, ctx));
                }
            }
            let end_time = tardis::chrono::Utc::now().timestamp_millis();
            let content = self.get_log_content(end_time, &mut ctx).await?;
            self.backend.log(content, &ctx)?;
            Ok((true, ctx))
        } else {
            Ok((true, ctx))
        }
    }
}

fn get_tardis_inst() -> TardisFunsInst {
    TardisFuns::inst(CODE.to_string(), None)
}

fn get_start_time_ext_code() -> String {
    format!("{CODE}:start_time")
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LogParamContent {
    pub op: String,
    pub key: Option<String>,
    pub name: String,
    pub user_id: Option<String>,
    pub role: Vec<SGRoleInfo>,
    pub ip: String,
    pub path: String,
    pub scheme: String,
    pub token: Option<String>,
    pub server_timing: Option<i64>,
    pub resp_status: String,
    //Indicates whether the business operation was successful.
    pub success: bool,
}

#[cfg(test)]
mod test {
    use spacegate_kernel::plugins::filters::{SgAttachedLevel, SgPluginFilter, SgPluginFilterInitDto};
    use spacegate_kernel::{
        http::{HeaderName, Uri},
        hyper::{Body, HeaderMap, Method, StatusCode, Version},
        plugins::context::SgRoutePluginContext,
    };
    use tardis::tokio;

    use crate::plugin::audit_log::get_start_time_ext_code;

    use super::SgFilterAuditLog;

    #[tokio::test]
    async fn test_log_content() {
        let ent_time = std::time::Instant::now();
        println!("test_log_content");
        let mut sg_filter_audit_log = SgFilterAuditLog::default();
        sg_filter_audit_log
            .init(&SgPluginFilterInitDto {
                gateway_name: "".to_string(),
                gateway_parameters: Default::default(),
                http_route_rules: vec![],
                attached_level: SgAttachedLevel::Gateway,
            })
            .await
            .unwrap();
        let guard = pprof::ProfilerGuardBuilder::default().frequency(100).blocklist(&["libc", "libgcc", "pthread", "vdso"]).build().unwrap();
        let end_time = 20100;
        let mut count = 0;
        loop {
            if count == 200000 {
                break;
            }
            count += 1;
            let mut header = HeaderMap::new();
            header.insert(sg_filter_audit_log.header_token_name.parse::<HeaderName>().unwrap(), "aaa".parse().unwrap());
            let mut ctx = SgRoutePluginContext::new_http(
                Method::POST,
                Uri::from_static("http://sg.idealworld.group/test1"),
                Version::HTTP_11,
                header,
                Body::from(""),
                "127.0.0.1:8080".parse().unwrap(),
                "".to_string(),
                None,
                None,
            );
            ctx.set_ext(&get_start_time_ext_code(), &20000.to_string());
            let mut ctx = ctx.resp(StatusCode::OK, HeaderMap::new(), Body::from(r#"{"code":"200","msg":"success"}"#));
            let log_content = sg_filter_audit_log.get_log_content(end_time, &mut ctx).await.unwrap();
            assert_eq!(log_content.token, Some("aaa".to_string()));
            assert_eq!(log_content.server_timing, Some(100));
            assert!(log_content.success);

            let mut header = HeaderMap::new();
            header.insert(sg_filter_audit_log.header_token_name.parse::<HeaderName>().unwrap(), "aaa".parse().unwrap());
            let ctx = SgRoutePluginContext::new_http(
                Method::POST,
                Uri::from_static("http://sg.idealworld.group/test1"),
                Version::HTTP_11,
                header,
                Body::from(""),
                "127.0.0.1:8080".parse().unwrap(),
                "".to_string(),
                None,
                None,
            );
            let mut ctx = ctx.resp(StatusCode::OK, HeaderMap::new(), Body::from(r#"{"code":200,"msg":"success"}"#));
            let log_content = sg_filter_audit_log.get_log_content(end_time, &mut ctx).await.unwrap();
            assert!(log_content.success);

            let mut header = HeaderMap::new();
            header.insert(sg_filter_audit_log.header_token_name.parse::<HeaderName>().unwrap(), "aaa".parse().unwrap());
            let ctx = SgRoutePluginContext::new_http(
                Method::POST,
                Uri::from_static("http://sg.idealworld.group/test1"),
                Version::HTTP_11,
                header,
                Body::from(""),
                "127.0.0.1:8080".parse().unwrap(),
                "".to_string(),
                None,
                None,
            );
            let mut ctx = ctx.resp(StatusCode::OK, HeaderMap::new(), Body::from(r#"{"code":"500","msg":"not success"}"#));
            let log_content = sg_filter_audit_log.get_log_content(end_time, &mut ctx).await.unwrap();
            assert!(!log_content.success);

            let mut header = HeaderMap::new();
            header.insert(sg_filter_audit_log.header_token_name.parse::<HeaderName>().unwrap(), "aaa".parse().unwrap());
            let ctx = SgRoutePluginContext::new_http(
                Method::POST,
                Uri::from_static("http://sg.idealworld.group/test1"),
                Version::HTTP_11,
                header,
                Body::from(""),
                "127.0.0.1:8080".parse().unwrap(),
                "".to_string(),
                None,
                None,
            );
            let mut ctx = ctx.resp(StatusCode::OK, HeaderMap::new(), Body::from(r#"{"code":500,"msg":"not success"}"#));
            let log_content = sg_filter_audit_log.get_log_content(end_time, &mut ctx).await.unwrap();
            assert!(!log_content.success);
        }
        if let Ok(report) = guard.report().build() {
            let file = std::fs::File::create("flamegraph.svg").unwrap();
            report.flamegraph(file).unwrap();
        };
        let exit_time = std::time::Instant::now();
        let time = exit_time.duration_since(ent_time);
        println!("test_log_content time:{:?}", time);
    }
}
