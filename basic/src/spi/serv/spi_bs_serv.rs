use async_trait::async_trait;
use tardis::{
    basic::{dto::TardisContext, result::TardisResult},
    db::sea_orm::{sea_query::*, EntityName, Set},
    TardisFunsInst,
};

use crate::{
    rbum::{
        domain::{rbum_cert, rbum_item, rbum_kind},
        dto::{
            rbum_cert_dto::{RbumCertAddReq, RbumCertModifyReq},
            rbum_filer_dto::{RbumCertFilterReq, RbumRelFilterReq},
            rbum_item_dto::{RbumItemKernelAddReq, RbumItemKernelModifyReq},
            rbum_rel_dto::RbumRelFindReq,
        },
        rbum_enumeration::{RbumCertRelKind, RbumCertStatusKind, RbumRelFromKind, RbumScopeLevelKind},
        serv::{rbum_cert_serv::RbumCertServ, rbum_crud_serv::RbumCrudOperation, rbum_item_serv::RbumItemCrudOperation, rbum_rel_serv::RbumRelServ},
    },
    spi::{
        domain::spi_bs,
        dto::spi_bs_dto::{SpiBsAddReq, SpiBsDetailResp, SpiBsFilterReq, SpiBsModifyReq, SpiBsSummaryResp},
        spi_constants::{SPI_CERT_KIND, SPI_IDENT_REL_TAG},
    },
};

pub struct SpiBsServ;

#[async_trait]
impl RbumItemCrudOperation<spi_bs::ActiveModel, SpiBsAddReq, SpiBsModifyReq, SpiBsSummaryResp, SpiBsSummaryResp, SpiBsFilterReq> for SpiBsServ {
    fn get_ext_table_name() -> &'static str {
        spi_bs::Entity.table_name()
    }

    fn get_rbum_kind_id() -> String {
        "".to_string()
    }

    fn get_rbum_domain_id() -> String {
        "".to_string()
    }

    async fn package_item_add(add_req: &SpiBsAddReq, funs: &TardisFunsInst, _: &TardisContext) -> TardisResult<RbumItemKernelAddReq> {
        Ok(RbumItemKernelAddReq {
            name: add_req.name.clone(),
            rel_rbum_kind_id: Some(add_req.kind_id.to_string()),
            rel_rbum_domain_id: Some(funs.module_code().to_string()),
            disabled: add_req.disabled,
            scope_level: Some(RbumScopeLevelKind::Root),
            ..Default::default()
        })
    }

    async fn package_ext_add(id: &str, add_req: &SpiBsAddReq, _: &TardisFunsInst, _: &TardisContext) -> TardisResult<spi_bs::ActiveModel> {
        Ok(spi_bs::ActiveModel {
            id: Set(id.to_string()),
            private: Set(add_req.private),
            ..Default::default()
        })
    }

    async fn after_add_item(id: &str, add_req: &mut SpiBsAddReq, funs: &TardisFunsInst, ctx: &TardisContext) -> TardisResult<()> {
        RbumCertServ::add_rbum(
            &mut RbumCertAddReq {
                ak: add_req.ak.clone(),
                sk: Some(add_req.sk.clone()),
                kind: Some(SPI_CERT_KIND.to_string()),
                supplier: Some(id.to_string()),
                conn_uri: Some(add_req.conn_uri.clone()),
                ext: Some(add_req.ext.clone()),
                rel_rbum_kind: RbumCertRelKind::Item,
                rel_rbum_id: id.to_string(),
                status: RbumCertStatusKind::Enabled,
                vcode: None,
                rel_rbum_cert_conf_id: None,
                start_time: None,
                end_time: None,
                is_outside: false,
            },
            funs,
            ctx,
        )
        .await?;
        Ok(())
    }

    async fn package_item_modify(_: &str, modify_req: &SpiBsModifyReq, _: &TardisFunsInst, _: &TardisContext) -> TardisResult<Option<RbumItemKernelModifyReq>> {
        if modify_req.name.is_none() && modify_req.disabled.is_none() {
            return Ok(None);
        }
        Ok(Some(RbumItemKernelModifyReq {
            code: None,
            name: modify_req.name.clone(),
            scope_level: None,
            disabled: modify_req.disabled,
        }))
    }

    async fn package_ext_modify(id: &str, modify_req: &SpiBsModifyReq, _: &TardisFunsInst, _: &TardisContext) -> TardisResult<Option<spi_bs::ActiveModel>> {
        if modify_req.private.is_none() {
            return Ok(None);
        }
        let mut spi_bs = spi_bs::ActiveModel {
            id: Set(id.to_string()),
            ..Default::default()
        };
        if let Some(private) = modify_req.private {
            spi_bs.private = Set(private);
        }
        Ok(Some(spi_bs))
    }

    async fn after_modify_item(id: &str, modify_req: &mut SpiBsModifyReq, funs: &TardisFunsInst, ctx: &TardisContext) -> TardisResult<()> {
        if let Some(cert) = RbumCertServ::find_one_rbum(
            &RbumCertFilterReq {
                kind: Some(SPI_CERT_KIND.to_string()),
                supplier: Some(vec![id.to_string()]),
                rel_rbum_kind: Some(RbumCertRelKind::Item),
                rel_rbum_id: Some(id.to_string()),
                ..Default::default()
            },
            funs,
            ctx,
        )
        .await?
        {
            RbumCertServ::modify_rbum(
                &cert.id,
                &mut RbumCertModifyReq {
                    ak: modify_req.ak.clone(),
                    sk: modify_req.sk.clone(),
                    conn_uri: modify_req.conn_uri.clone(),
                    ext: modify_req.ext.clone(),
                    status: None,
                    start_time: None,
                    end_time: None,
                },
                funs,
                ctx,
            )
            .await?;
        }
        Ok(())
    }

    async fn package_ext_query(query: &mut SelectStatement, _: bool, filter: &SpiBsFilterReq, _: &TardisFunsInst, _: &TardisContext) -> TardisResult<()> {
        query
            .column((spi_bs::Entity, spi_bs::Column::Private))
            .expr_as(Expr::tbl(rbum_kind::Entity, rbum_kind::Column::Id), Alias::new("kind_id"))
            .expr_as(Expr::tbl(rbum_kind::Entity, rbum_kind::Column::Code), Alias::new("kind_code"))
            .expr_as(Expr::tbl(rbum_kind::Entity, rbum_kind::Column::Name), Alias::new("kind_name"))
            .column((rbum_cert::Entity, rbum_cert::Column::ConnUri))
            .column((rbum_cert::Entity, rbum_cert::Column::Ak))
            .column((rbum_cert::Entity, rbum_cert::Column::Sk))
            .column((rbum_cert::Entity, rbum_cert::Column::Ext))
            .left_join(
                rbum_kind::Entity,
                Expr::tbl(rbum_kind::Entity, rbum_kind::Column::Id).equals(rbum_item::Entity, rbum_item::Column::RelRbumKindId),
            )
            .left_join(
                rbum_cert::Entity,
                Condition::all()
                    .add(Expr::tbl(rbum_cert::Entity, rbum_cert::Column::Kind).eq(SPI_CERT_KIND))
                    .add(Expr::tbl(rbum_cert::Entity, rbum_cert::Column::RelRbumKind).eq(RbumCertRelKind::Item.to_int()))
                    .add(Expr::tbl(rbum_cert::Entity, rbum_cert::Column::Supplier).equals(spi_bs::Entity, spi_bs::Column::Id))
                    .add(Expr::tbl(rbum_cert::Entity, rbum_cert::Column::RelRbumId).equals(spi_bs::Entity, spi_bs::Column::Id)),
            );
        if let Some(private) = filter.private {
            query.and_where(Expr::tbl(spi_bs::Entity, spi_bs::Column::Private).eq(private));
        }
        Ok(())
    }
}

impl SpiBsServ {
    pub async fn get_bs(id: &str, funs: &TardisFunsInst, ctx: &TardisContext) -> TardisResult<SpiBsDetailResp> {
        let bs = Self::get_item(id, &SpiBsFilterReq::default(), funs, ctx).await?;
        let app_tenant_ids = RbumRelServ::find_rbums(
            &RbumRelFilterReq {
                tag: Some(SPI_IDENT_REL_TAG.to_string()),
                from_rbum_kind: Some(RbumRelFromKind::Item),
                from_rbum_id: Some(id.to_string()),
                ..Default::default()
            },
            None,
            None,
            funs,
            ctx,
        )
        .await?
        .into_iter()
        .map(|rel| rel.to_rbum_item_id)
        .collect::<Vec<String>>();
        Ok(SpiBsDetailResp {
            id: bs.id,
            name: bs.name,
            kind_id: bs.kind_id,
            kind_code: bs.kind_code,
            kind_name: bs.kind_name,
            conn_uri: bs.conn_uri,
            ak: bs.ak,
            sk: bs.sk,
            ext: bs.ext,
            private: bs.private,
            disabled: bs.disabled,
            create_time: bs.create_time,
            update_time: bs.update_time,
            rel_app_tenant_ids: app_tenant_ids,
        })
    }

    pub async fn add_rel(bs_id: &str, app_tenant_id: &str, funs: &TardisFunsInst, ctx: &TardisContext) -> TardisResult<()> {
        if !RbumRelServ::exist_simple_rel(
            &RbumRelFindReq {
                tag: Some(SPI_IDENT_REL_TAG.to_string()),
                from_rbum_kind: Some(RbumRelFromKind::Item),
                from_rbum_id: Some(bs_id.to_string()),
                to_rbum_item_id: Some(app_tenant_id.to_string()),
                ..Default::default()
            },
            funs,
            ctx,
        )
        .await?
        {
            RbumRelServ::add_simple_rel(SPI_IDENT_REL_TAG, bs_id, app_tenant_id, funs, ctx).await?;
        }
        Ok(())
    }

    pub async fn delete_rel(bs_id: &str, app_tenant_id: &str, funs: &TardisFunsInst, ctx: &TardisContext) -> TardisResult<()> {
        let ids = RbumRelServ::find_id_rbums(
            &RbumRelFilterReq {
                tag: Some(SPI_IDENT_REL_TAG.to_string()),
                from_rbum_kind: Some(RbumRelFromKind::Item),
                from_rbum_id: Some(bs_id.to_string()),
                to_rbum_item_id: Some(app_tenant_id.to_string()),
                ..Default::default()
            },
            None,
            None,
            funs,
            ctx,
        )
        .await?;
        for id in ids {
            RbumRelServ::delete_rbum(&id, funs, ctx).await?;
        }
        Ok(())
    }
}
