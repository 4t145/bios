use tardis::basic::dto::TardisContext;
use tardis::web::context_extractor::TardisContextExtractor;
use tardis::web::poem::web::Path;
use tardis::web::poem_openapi::{payload::Json, OpenApi};
use tardis::web::web_resp::{TardisApiResult, TardisResp, Void};

use crate::basic::dto::iam_account_dto::AccountInfoResp;
use crate::basic::dto::iam_cert_dto::{IamContextFetchReq, IamMailVCodeCertActivateReq, IamMailVCodeCertAddReq, IamMailVCodeCertResendActivationReq, IamUserPwdCertModifyReq};
use crate::basic::serv::iam_cert_serv::IamCertServ;
use crate::console_passport::dto::iam_cp_cert_dto::{IamCpMailVCodeLoginGenVCodeReq, IamCpMailVCodeLoginReq, IamCpUserPwdLoginReq};
use crate::console_passport::serv::iam_cp_cert_mail_vcode_serv::IamCpCertMailVCodeServ;
use crate::console_passport::serv::iam_cp_cert_user_pwd_serv::IamCpCertUserPwdServ;
use crate::iam_constants;

pub struct IamCpAccountApi;

/// Personal Console Cert API
#[OpenApi(prefix_path = "/cp/cert", tag = "crate::iam_enumeration::Tag::Passport")]
impl IamCpAccountApi {
    /// Fetch TardisContext By Token
    #[oai(path = "/cp/context", method = "get")]
    async fn fetch_context(&self, fetch_req: Json<IamContextFetchReq>) -> TardisApiResult<TardisContext> {
        let funs = iam_constants::get_tardis_inst();
        let cxt = IamCertServ::fetch_context(&fetch_req.0, &funs).await?;
        TardisResp::ok(cxt)
    }

    /// Modify Password
    #[oai(path = "/userpwd", method = "put")]
    async fn modify_cert_user_pwd(&self, mut modify_req: Json<IamUserPwdCertModifyReq>, cxt: TardisContextExtractor) -> TardisApiResult<Void> {
        let mut funs = iam_constants::get_tardis_inst();
        funs.begin().await?;
        IamCpCertUserPwdServ::modify_cert_user_pwd(&mut modify_req.0, &funs, &cxt.0).await?;
        funs.commit().await?;
        TardisResp::ok(Void {})
    }

    /// Login by Username and Password
    #[oai(path = "/login/userpwd", method = "put")]
    async fn login_by_user_pwd(&self, login_req: Json<IamCpUserPwdLoginReq>) -> TardisApiResult<AccountInfoResp> {
        let mut funs = iam_constants::get_tardis_inst();
        funs.begin().await?;
        let resp = IamCpCertUserPwdServ::login_by_user_pwd(&login_req.0, &funs).await?;
        funs.commit().await?;
        TardisResp::ok(resp)
    }

    /// Add Mail-VCode Cert
    #[oai(path = "/mailvcode", method = "put")]
    async fn add_mail_vcode_cert(&self, add_req: Json<IamMailVCodeCertAddReq>, cxt: TardisContextExtractor) -> TardisApiResult<Void> {
        let mut funs = iam_constants::get_tardis_inst();
        funs.begin().await?;
        IamCpCertMailVCodeServ::add_cert_mail_vocde(&add_req.0, &funs, &cxt.0).await?;
        funs.commit().await?;
        TardisResp::ok(Void {})
    }

    /// Delete Mail-VCode Cert
    #[oai(path = "/mailvcode/:id", method = "delete")]
    async fn delete_mail_vcode_cert(&self, id: Path<String>, cxt: TardisContextExtractor) -> TardisApiResult<Void> {
        let mut funs = iam_constants::get_tardis_inst();
        funs.begin().await?;
        IamCpCertMailVCodeServ::delete_cert_mail_vocde(&id.0, &funs, &cxt.0).await?;
        funs.commit().await?;
        TardisResp::ok(Void {})
    }

    /// Resend Activation Mail
    #[oai(path = "/mailvcode/resend", method = "put")]
    async fn resend_activation_mail(&self, req: Json<IamMailVCodeCertResendActivationReq>, cxt: TardisContextExtractor) -> TardisApiResult<Void> {
        let funs = iam_constants::get_tardis_inst();
        IamCpCertMailVCodeServ::resend_activation_mail(&req.0.mail, &funs, &cxt.0).await?;
        TardisResp::ok(Void {})
    }

    /// Activate Mail
    #[oai(path = "/mailvcode/activate", method = "put")]
    async fn activate_mail(&self, req: Json<IamMailVCodeCertActivateReq>, cxt: TardisContextExtractor) -> TardisApiResult<Void> {
        let mut funs = iam_constants::get_tardis_inst();
        funs.begin().await?;
        IamCpCertMailVCodeServ::activate_mail(&req.0.mail, &req.0.vcode, &funs, &cxt.0).await?;
        funs.commit().await?;
        TardisResp::ok(Void {})
    }

    /// Send Login Mail
    #[oai(path = "/login/mailvcode/vcode", method = "post")]
    async fn send_login_mail(&self, login_req: Json<IamCpMailVCodeLoginGenVCodeReq>) -> TardisApiResult<Void> {
        let mut funs = iam_constants::get_tardis_inst();
        funs.begin().await?;
        IamCpCertMailVCodeServ::send_login_mail(&login_req.0, &funs).await?;
        funs.commit().await?;
        TardisResp::ok(Void {})
    }

    /// Login by Mail And Vcode
    #[oai(path = "/login/mailvcode", method = "put")]
    async fn login_by_mail_vocde(&self, login_req: Json<IamCpMailVCodeLoginReq>) -> TardisApiResult<AccountInfoResp> {
        let mut funs = iam_constants::get_tardis_inst();
        funs.begin().await?;
        let resp = IamCpCertMailVCodeServ::login_by_mail_vocde(&login_req.0, &funs).await?;
        funs.commit().await?;
        TardisResp::ok(resp)
    }
}
