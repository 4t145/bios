use bios_sdk_invoke::clients::spi_log_client;
use serde::{Deserialize, Serialize};
use spacegate_kernel::plugins::context::SgRoutePluginContext;
use tardis::{
    basic::{dto::TardisContext, result::TardisResult},
    log,
    serde_json::json,
    tokio, TardisFuns,
};

use super::{get_tardis_inst, LogParamContent};

pub trait LogBackend {
    fn log(&self, content: LogParamContent, ctx: &SgRoutePluginContext) -> TardisResult<()>;
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "backend")]
pub enum LogBackendEnum {
    Spi(LogBackendSpi),
    Tracing(LogBackendTracing),
}

impl Default for LogBackendEnum {
    fn default() -> Self {
        LogBackendEnum::Tracing(LogBackendTracing)
    }
}

impl LogBackendEnum {
    pub fn log(&self, content: LogParamContent, ctx: &SgRoutePluginContext) -> TardisResult<()> {
        match self {
            LogBackendEnum::Spi(b) => b.log(content, ctx),
            LogBackendEnum::Tracing(b) => b.log(content, ctx),
        }
    }
}
#[derive(Debug, Serialize, Deserialize)]
pub struct LogBackendTracing;

impl LogBackend for LogBackendTracing {
    fn log(&self, content: LogParamContent, ctx: &SgRoutePluginContext) -> TardisResult<()> {
        log::info!(
            "[Plugin.AuditLog] name:{}, user_id:{}, ip:{}, op:{}, path:{}, resp_status:{}, success:{}",
            content.name,
            content.user_id.unwrap_or_default(),
            content.ip,
            ctx.request.get_method(),
            content.path,
            content.resp_status,
            content.success,
        );
        Ok(())
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct LogBackendSpi {
    pub log_url: String,
    pub spi_app_id: String,
    pub tag: String,
}

impl Default for LogBackendSpi {
    fn default() -> Self {
        LogBackendSpi {
            log_url: "".into(),
            spi_app_id: "".into(),
            tag: "gateway".into(),
        }    
    }
}

impl LogBackend for LogBackendSpi {
    fn log(&self, content: LogParamContent, ctx: &SgRoutePluginContext) -> TardisResult<()> {
        let funs = get_tardis_inst();
        let spi_ctx = TardisContext {
            owner: ctx.get_cert_info().map(|info| info.id.clone()).unwrap_or_default(),
            roles: ctx.get_cert_info().map(|info| info.roles.clone().into_iter().map(|r| r.id).collect()).unwrap_or_default(),
            ..Default::default()
        };
        let op = ctx.request.get_method().to_string();
        let log_ext = json!({
            "name":content.name,
            "id":content.user_id,
            "ip":content.ip,
            "op":op.clone(),
            "path":content.path,
            "resp_status": content.resp_status,
            "success":content.success,
        });
        let tag = self.tag.clone();
        tokio::task::spawn(async move {
            match spi_log_client::SpiLogClient::add(
                &tag,
                &TardisFuns::json.obj_to_string(&content).unwrap_or_default(),
                Some(log_ext),
                None,
                None,
                Some(op),
                None,
                Some(tardis::chrono::Utc::now().to_rfc3339()),
                content.user_id,
                None,
                &funs,
                &spi_ctx,
            )
            .await
            {
                Ok(_) => {
                    log::trace!("[Plugin.AuditLog] add log success")
                }
                Err(e) => {
                    log::warn!("[Plugin.AuditLog] failed to add log:{e}")
                }
            };
        });
        Ok(())
    }
}
