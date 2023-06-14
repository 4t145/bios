use bios_basic::rbum::dto::rbum_filer_dto::RbumBasicFilterReq;
use bios_basic::rbum::serv::rbum_item_serv::RbumItemCrudOperation;
use tardis::web::context_extractor::TardisContextExtractor;
use tardis::web::poem_openapi;
use tardis::web::poem_openapi::param::{Path, Query};
use tardis::web::poem_openapi::payload::Json;
use tardis::web::web_resp::{TardisApiResult, TardisPage, TardisResp, Void};

use crate::dto::flow_model_dto::{FlowModelAddReq, FlowModelDetailResp, FlowModelFilterReq, FlowModelModifyReq, FlowModelModifyStateReq, FlowModelSummaryResp};
use crate::dto::flow_transition_dto::{FlowTransitionAddReq, FlowTransitionModifyReq};
use crate::dto::flow_var_dto::FlowVarInfo;
use crate::flow_constants;
use crate::serv::flow_model_serv::FlowModelServ;

pub struct FlowCcModelApi;

/// Flow model process API
#[poem_openapi::OpenApi(prefix_path = "/cc/model")]
impl FlowCcModelApi {
    /// Add Model / 添加模型
    #[oai(path = "/", method = "post")]
    async fn add(&self, mut add_req: Json<FlowModelAddReq>, ctx: TardisContextExtractor) -> TardisApiResult<String> {
        let mut funs = flow_constants::get_tardis_inst();
        funs.begin().await?;
        let result = FlowModelServ::add_item(&mut add_req.0, &funs, &ctx.0).await?;
        funs.commit().await?;
        TardisResp::ok(result)
    }

    /// Modify Model By Model Id / 修改模型
    #[oai(path = "/:flow_model_id", method = "patch")]
    async fn modify(&self, flow_model_id: Path<String>, mut modify_req: Json<FlowModelModifyReq>, ctx: TardisContextExtractor) -> TardisApiResult<Void> {
        let mut funs = flow_constants::get_tardis_inst();
        funs.begin().await?;
        FlowModelServ::modify_item(&flow_model_id.0, &mut modify_req.0, &funs, &ctx.0).await?;
        funs.commit().await?;
        TardisResp::ok(Void {})
    }

    /// Get Model By Model Id / 获取模型
    #[oai(path = "/:flow_model_id", method = "get")]
    async fn get(&self, flow_model_id: Path<String>, ctx: TardisContextExtractor) -> TardisApiResult<FlowModelDetailResp> {
        let funs = flow_constants::get_tardis_inst();
        let result = FlowModelServ::get_item(
            &flow_model_id.0,
            &FlowModelFilterReq {
                basic: RbumBasicFilterReq {
                    with_sub_own_paths: true,
                    ..Default::default()
                },
                ..Default::default()
            },
            &funs,
            &ctx.0,
        )
        .await?;
        TardisResp::ok(result)
    }

    /// Find Models / 获取模型列表
    #[oai(path = "/", method = "get")]
    #[allow(clippy::too_many_arguments)]
    async fn paginate(
        &self,
        flow_model_ids: Query<Option<String>>,
        name: Query<Option<String>>,
        tag: Query<Option<String>>,
        enabled: Query<Option<bool>>,
        with_sub: Query<Option<bool>>,
        page_number: Query<u32>,
        page_size: Query<u32>,
        desc_by_create: Query<Option<bool>>,
        desc_by_update: Query<Option<bool>>,
        ctx: TardisContextExtractor,
    ) -> TardisApiResult<TardisPage<FlowModelSummaryResp>> {
        let funs = flow_constants::get_tardis_inst();
        let result = FlowModelServ::paginate_items(
            &FlowModelFilterReq {
                basic: RbumBasicFilterReq {
                    ids: flow_model_ids.0.map(|ids| ids.split(',').map(|id| id.to_string()).collect::<Vec<String>>()),
                    name: name.0,
                    with_sub_own_paths: with_sub.0.unwrap_or(false),
                    enabled: enabled.0,
                    ..Default::default()
                },
                tag: tag.0,
            },
            page_number.0,
            page_size.0,
            desc_by_create.0,
            desc_by_update.0,
            &funs,
            &ctx.0,
        )
        .await?;
        TardisResp::ok(result)
    }

    /// Delete Model By Model Id / 删除模型
    ///
    /// Valid only when model is not used
    ///
    /// 仅在模型没被使用时有效
    #[oai(path = "/:flow_model_id", method = "delete")]
    async fn delete(&self, flow_model_id: Path<String>, ctx: TardisContextExtractor) -> TardisApiResult<Void> {
        let mut funs = flow_constants::get_tardis_inst();
        funs.begin().await?;
        FlowModelServ::delete_item(&flow_model_id.0, &funs, &ctx.0).await?;
        funs.commit().await?;
        TardisResp::ok(Void {})
    }

    /// Modify State By Model Id / 编辑状态
    #[oai(path = "/:flow_model_id/state", method = "patch")]
    async fn modify_state(&self, flow_model_id: Path<String>, mut modify_req: Json<FlowModelModifyStateReq>, ctx: TardisContextExtractor) -> TardisApiResult<Void> {
        let mut funs = flow_constants::get_tardis_inst();
        funs.begin().await?;
        FlowModelServ::modify_state(&flow_model_id.0, &mut modify_req, &funs, &ctx.0).await?;
        funs.commit().await?;
        TardisResp::ok(Void {})
    }

    /// 指定状态添加动作
    #[oai(path = "/:flow_model_id/transition", method = "post")]
    async fn add_transition(&self, flow_model_id: Path<String>, add_req: Json<FlowTransitionAddReq>, ctx: TardisContextExtractor) -> TardisApiResult<Void> {
        let mut funs = flow_constants::get_tardis_inst();
        funs.begin().await?;
        FlowModelServ::add_transitions(&flow_model_id.0, &vec![add_req.0], &funs, &ctx.0).await?;
        funs.commit().await?;
        TardisResp::ok(Void {})
    }

    /// 指定状态编辑动作
    #[oai(path = "/:flow_model_id/transition", method = "patch")]
    async fn modify_transition(&self, flow_model_id: Path<String>, modify_req: Json<FlowTransitionModifyReq>, ctx: TardisContextExtractor) -> TardisApiResult<Void> {
        let mut funs = flow_constants::get_tardis_inst();
        funs.begin().await?;
        FlowModelServ::modify_transitions(&flow_model_id.0, &vec![modify_req.0], &funs, &ctx.0).await?;
        funs.commit().await?;
        TardisResp::ok(Void {})
    }

    /// 指定状态删除动作
    #[oai(path = "/:flow_model_id/transition/:transition_id", method = "delete")]
    async fn delete_transitions(&self, flow_model_id: Path<String>, transition_id: Path<String>, ctx: TardisContextExtractor) -> TardisApiResult<Void> {
        let mut funs = flow_constants::get_tardis_inst();
        funs.begin().await?;
        FlowModelServ::delete_transitions(&flow_model_id.0, &vec![transition_id.0], &funs, &ctx.0).await?;
        funs.commit().await?;
        TardisResp::ok(Void {})
    }

    /// 指定状态设为初始
    #[oai(path = "/:flow_model_id/init_state/:state_id", method = "patch")]
    async fn modify_init_state(&self, flow_model_id: Path<String>, state_id: Path<String>, ctx: TardisContextExtractor) -> TardisApiResult<Void> {
        let mut funs = flow_constants::get_tardis_inst();
        funs.begin().await?;
        FlowModelServ::modify_init_state(&flow_model_id.0, &state_id.0, &funs, &ctx.0).await?;
        funs.commit().await?;
        TardisResp::ok(Void {})
    }

    /// 指定动作编辑验证表单
    #[oai(path = "/:flow_model_id/transition/:transition_id/var", method = "patch")]
    async fn modify_transition_var(
        &self,
        flow_model_id: Path<String>,
        transition_id: Path<String>,
        modify_req: Json<Vec<FlowVarInfo>>,
        ctx: TardisContextExtractor,
    ) -> TardisApiResult<Void> {
        let mut funs = flow_constants::get_tardis_inst();
        funs.begin().await?;
        FlowModelServ::modify_transition_var(&flow_model_id.0, &transition_id.0, modify_req.0, &funs, &ctx.0).await?;
        funs.commit().await?;
        TardisResp::ok(Void {})
    }
}
// 指定动作编辑验证表单
