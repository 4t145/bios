use tardis::basic::dto::TardisContext;
use tardis::basic::field::TrimString;
use tardis::basic::result::TardisResult;
use tardis::log::info;
use tardis::rand::Rng;
use tardis::TardisFunsInst;

use bios_basic::rbum::dto::rbum_cert_conf_dto::{RbumCertConfAddReq, RbumCertConfModifyReq};
use bios_basic::rbum::dto::rbum_cert_dto::{RbumCertAddReq, RbumCertModifyReq};
use bios_basic::rbum::dto::rbum_filer_dto::{RbumCertConfFilterReq, RbumCertFilterReq};
use bios_basic::rbum::rbum_enumeration::{RbumCertConfStatusKind, RbumCertRelKind, RbumCertStatusKind};
use bios_basic::rbum::serv::rbum_cert_serv::{RbumCertConfServ, RbumCertServ};
use bios_basic::rbum::serv::rbum_crud_serv::RbumCrudOperation;
use bios_basic::rbum::serv::rbum_item_serv::RbumItemCrudOperation;

use crate::basic::dto::iam_cert_conf_dto::IamCertConfMailVCodeAddOrModifyReq;
use crate::basic::dto::iam_cert_dto::IamCertMailVCodeAddReq;
use crate::basic::dto::iam_filer_dto::IamAccountFilterReq;
use crate::basic::serv::iam_account_serv::IamAccountServ;
use crate::basic::serv::iam_cert_serv::IamCertServ;
use crate::basic::serv::iam_tenant_serv::IamTenantServ;
use crate::iam_config::IamBasicConfigApi;
use crate::iam_constants;
use crate::iam_enumeration::IamCertKernelKind;

use super::clients::mail_client::MailClient;
use super::clients::spi_log_client::{LogParamContent, LogParamOp, LogParamTag, SpiLogClient};

pub struct IamCertMailVCodeServ;

impl IamCertMailVCodeServ {
    pub async fn add_cert_conf(add_req: &IamCertConfMailVCodeAddOrModifyReq, rel_iam_item_id: Option<String>, funs: &TardisFunsInst, ctx: &TardisContext) -> TardisResult<String> {
        let id = RbumCertConfServ::add_rbum(
            &mut RbumCertConfAddReq {
                kind: TrimString(IamCertKernelKind::MailVCode.to_string()),
                supplier: None,
                name: TrimString(IamCertKernelKind::MailVCode.to_string()),
                note: None,
                ak_note: add_req.ak_note.clone(),
                ak_rule: add_req.ak_rule.clone(),
                sk_note: None,
                sk_rule: None,
                ext: None,
                sk_need: Some(false),
                sk_dynamic: Some(true),
                sk_encrypted: Some(false),
                repeatable: None,
                is_basic: Some(false),
                is_ak_repeatable: None,
                rest_by_kinds: None,
                expire_sec: None,
                sk_lock_cycle_sec: None,
                sk_lock_err_times: None,
                sk_lock_duration_sec: None,
                coexist_num: Some(1),
                conn_uri: None,
                status: RbumCertConfStatusKind::Enabled,
                rel_rbum_domain_id: funs.iam_basic_domain_iam_id(),
                rel_rbum_item_id: rel_iam_item_id,
            },
            funs,
            ctx,
        )
        .await?;
        Ok(id)
    }

    pub async fn modify_cert_conf(id: &str, modify_req: &IamCertConfMailVCodeAddOrModifyReq, funs: &TardisFunsInst, ctx: &TardisContext) -> TardisResult<()> {
        RbumCertConfServ::modify_rbum(
            id,
            &mut RbumCertConfModifyReq {
                name: None,
                note: None,
                ak_note: modify_req.ak_note.clone(),
                ak_rule: modify_req.ak_rule.clone(),
                sk_note: None,
                sk_rule: None,
                ext: None,
                sk_need: None,
                sk_encrypted: None,
                repeatable: None,
                is_basic: None,
                rest_by_kinds: None,
                expire_sec: None,
                sk_lock_cycle_sec: None,
                sk_lock_err_times: None,
                sk_lock_duration_sec: None,
                coexist_num: None,
                conn_uri: None,
                status: None,
            },
            funs,
            ctx,
        )
        .await?;
        Ok(())
    }

    pub async fn add_cert(add_req: &IamCertMailVCodeAddReq, account_id: &str, rel_rbum_cert_conf_id: &str, funs: &TardisFunsInst, ctx: &TardisContext) -> TardisResult<String> {
        let vcode = Self::get_vcode();
        let id = RbumCertServ::add_rbum(
            &mut RbumCertAddReq {
                ak: TrimString(add_req.mail.trim().to_string()),
                sk: None,
                kind: None,
                supplier: None,
                vcode: Some(TrimString(vcode.clone())),
                ext: None,
                start_time: None,
                end_time: None,
                conn_uri: None,
                status: RbumCertStatusKind::Pending,
                rel_rbum_cert_conf_id: Some(rel_rbum_cert_conf_id.to_string()),
                rel_rbum_kind: RbumCertRelKind::Item,
                rel_rbum_id: account_id.to_string(),
                is_outside: false,
                is_ignore_check_sk: false,
            },
            funs,
            ctx,
        )
        .await?;
        Self::send_activation_mail(account_id, &add_req.mail, &vcode, funs, ctx).await?;
        Ok(id)
    }

    pub async fn resend_activation_mail(account_id: &str, mail: &str, funs: &TardisFunsInst, ctx: &TardisContext) -> TardisResult<()> {
        let vcode = Self::get_vcode();
        RbumCertServ::add_vcode_to_cache(mail, &vcode, &ctx.own_paths, funs).await?;
        Self::send_activation_mail(account_id, mail, &vcode, funs, ctx).await
    }

    async fn send_activation_mail(account_id: &str, mail: &str, vcode: &str, funs: &TardisFunsInst, ctx: &TardisContext) -> TardisResult<()> {
        let account_name = IamAccountServ::peek_item(account_id, &IamAccountFilterReq::default(), funs, ctx).await?.name;
        MailClient::send_cert_activate_vcode(mail, Some(account_name), vcode, funs).await?;
        Ok(())
    }

    pub async fn activate_mail(mail: &str, input_vcode: &str, funs: &TardisFunsInst, ctx: &TardisContext) -> TardisResult<()> {
        if let Some(cached_vcode) = RbumCertServ::get_and_delete_vcode_in_cache(mail, &ctx.own_paths, funs).await? {
            if cached_vcode == input_vcode {
                let cert = RbumCertServ::find_one_rbum(
                    &RbumCertFilterReq {
                        ak: Some(mail.to_string()),
                        status: Some(RbumCertStatusKind::Pending),
                        rel_rbum_kind: Some(RbumCertRelKind::Item),
                        rel_rbum_cert_conf_ids: Some(vec![
                            IamCertServ::get_cert_conf_id_by_kind(IamCertKernelKind::MailVCode.to_string().as_str(), Some(IamTenantServ::get_id_by_ctx(ctx, funs)?), funs).await?,
                        ]),
                        ..Default::default()
                    },
                    funs,
                    ctx,
                )
                .await?;
                return if let Some(cert) = cert {
                    RbumCertServ::modify_rbum(
                        &cert.id,
                        &mut RbumCertModifyReq {
                            status: Some(RbumCertStatusKind::Enabled),
                            ak: None,
                            sk: None,
                            ext: None,
                            start_time: None,
                            end_time: None,
                            conn_uri: None,
                        },
                        funs,
                        ctx,
                    )
                    .await?;
                    Ok(())
                } else {
                    Err(funs.err().not_found(
                        "iam_cert_mail_vcode",
                        "activate",
                        &format!("not found credential of kind {:?}", IamCertKernelKind::MailVCode),
                        "404-iam-cert-kind-not-exist",
                    ))
                };
            }
        }
        Err(funs.err().unauthorized("iam_cert_mail_vcode", "activate", "email or verification code error", "401-iam-cert-valid"))
    }

    pub async fn send_bind_mail(mail: &str, funs: &TardisFunsInst, ctx: &TardisContext) -> TardisResult<()> {
        let ctx = IamAccountServ::new_context_if_account_is_global(ctx, funs).await?;
        if RbumCertServ::count_rbums(
            &RbumCertFilterReq {
                ak: Some(mail.to_string()),
                rel_rbum_kind: Some(RbumCertRelKind::Item),
                rel_rbum_cert_conf_ids: Some(vec![
                    IamCertServ::get_cert_conf_id_by_kind(IamCertKernelKind::MailVCode.to_string().as_str(), Some(IamTenantServ::get_id_by_ctx(&ctx, funs)?), funs).await?,
                ]),
                ..Default::default()
            },
            funs,
            &ctx,
        )
        .await?
            > 0
        {
            return Err(funs.err().unauthorized("iam_cert_mail_vcode", "activate", "email already exist", "401-iam-cert-valid"));
        }
        let vcode = Self::get_vcode();
        let account_name = IamAccountServ::peek_item(&ctx.owner, &IamAccountFilterReq::default(), funs, &ctx).await?.name;
        RbumCertServ::add_vcode_to_cache(mail, &vcode, &ctx.own_paths, funs).await?;
        MailClient::send_cert_activate_vcode(mail, Some(account_name), &vcode, funs).await?;
        Ok(())
    }

    pub async fn bind_mail(mail: &str, input_vcode: &str, funs: &TardisFunsInst, ctx: &TardisContext) -> TardisResult<String> {
        let ctx = IamAccountServ::new_context_if_account_is_global(ctx, funs).await?;
        if let Some(cached_vcode) = RbumCertServ::get_and_delete_vcode_in_cache(mail, &ctx.own_paths, funs).await? {
            if cached_vcode == input_vcode {
                let rel_rbum_cert_conf_id =
                    IamCertServ::get_cert_conf_id_by_kind(IamCertKernelKind::MailVCode.to_string().as_str(), Some(IamTenantServ::get_id_by_ctx(&ctx, funs)?), funs).await?;
                let id = RbumCertServ::add_rbum(
                    &mut RbumCertAddReq {
                        ak: TrimString(mail.trim().to_string()),
                        sk: None,
                        kind: None,
                        supplier: None,
                        vcode: Some(TrimString(input_vcode.to_string())),
                        ext: None,
                        start_time: None,
                        end_time: None,
                        conn_uri: None,
                        status: RbumCertStatusKind::Enabled,
                        rel_rbum_cert_conf_id: Some(rel_rbum_cert_conf_id),
                        rel_rbum_kind: RbumCertRelKind::Item,
                        rel_rbum_id: ctx.owner.clone(),
                        is_outside: false,
                        is_ignore_check_sk: false,
                    },
                    funs,
                    &ctx,
                )
                .await?;
                let op_describe = format!("绑定邮箱为{}", mail);
                let owner = ctx.owner.to_string();
                let ctx_clone = ctx.clone();
                ctx.add_async_task(Box::new(|| {
                    Box::pin(async move {
                        let funs = iam_constants::get_tardis_inst();
                        SpiLogClient::add_item(
                            LogParamTag::IamAccount,
                            LogParamContent {
                                op: op_describe,
                                ext: Some(owner.clone()),
                                ..Default::default()
                            },
                            None,
                            Some(owner.clone()),
                            LogParamOp::Modify,
                            None,
                            Some(tardis::chrono::Utc::now().to_rfc3339()),
                            &funs,
                            &ctx_clone,
                        )
                        .await
                        .unwrap();
                    })
                }))
                .await
                .unwrap();

                return Ok(id);
            }
        }
        Err(funs.err().unauthorized("iam_cert_mail_vcode", "activate", "email or verification code error", "401-iam-cert-valid"))
    }

    pub async fn send_login_mail(mail: &str, own_paths: &str, funs: &TardisFunsInst) -> TardisResult<()> {
        let vcode = Self::get_vcode();
        RbumCertServ::add_vcode_to_cache(mail, &vcode, own_paths, funs).await?;
        MailClient::send_vcode(mail, None, &vcode, funs).await?;
        Ok(())
    }

    fn get_vcode() -> String {
        let mut rand = tardis::rand::thread_rng();
        let vcode: i32 = rand.gen_range(1000..9999);
        format!("{vcode}")
    }

    pub async fn add_or_enable_cert_conf(
        add_req: &IamCertConfMailVCodeAddOrModifyReq,
        rel_iam_item_id: Option<String>,
        funs: &TardisFunsInst,
        ctx: &TardisContext,
    ) -> TardisResult<String> {
        let cert_result = RbumCertConfServ::do_find_one_rbum(
            &RbumCertConfFilterReq {
                kind: Some(TrimString(IamCertKernelKind::MailVCode.to_string())),
                rel_rbum_item_id: rel_iam_item_id.clone(),
                ..Default::default()
            },
            funs,
            ctx,
        )
        .await?;
        let result = if let Some(cert_result) = cert_result {
            IamCertServ::enabled_cert_conf(&cert_result.id, funs, ctx).await?;
            cert_result.id
        } else {
            Self::add_cert_conf(add_req, rel_iam_item_id, funs, ctx).await?
        };
        Ok(result)
    }

    pub async fn send_pwd(account_id: &str, pwd: &str, funs: &TardisFunsInst, ctx: &TardisContext) -> TardisResult<()> {
        let resp = IamCertServ::get_kernel_cert(account_id, &IamCertKernelKind::PhoneVCode, funs, ctx).await;
        match resp {
            Ok(cert) => {
                let _ = MailClient::send_pwd(&cert.ak, pwd, funs).await;
            }
            Err(_) => info!("mail pwd not found"),
        }
        Ok(())
    }
}
