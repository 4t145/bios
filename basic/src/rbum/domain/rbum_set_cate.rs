use tardis::basic::dto::TardisContext;
use tardis::db::reldb_client::TardisActiveModel;
use tardis::db::sea_orm::prelude::*;
use tardis::db::sea_orm::*;
use tardis::db::sea_query::{ColumnDef, Index, IndexCreateStatement, Table, TableCreateStatement};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "rbum_set_cate")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    // Specific
    pub sys_code: String,
    pub bus_code: String,
    pub name: String,
    pub icon: String,
    pub sort: u32,
    pub ext: String,
    pub rel_rbum_set_id: String,
    // Basic
    pub own_paths: String,
    pub owner: String,
    pub create_time: DateTime,
    pub update_time: DateTime,
    // With Scope
    pub scope_level: i8,
}

impl TardisActiveModel for ActiveModel {
    fn fill_cxt(&mut self, cxt: &TardisContext, is_insert: bool) {
        if is_insert {
            self.own_paths = Set(cxt.own_paths.to_string());
            self.owner = Set(cxt.owner.to_string());
        }
    }

    fn create_table_statement(_: DbBackend) -> TableCreateStatement {
        Table::create()
            .table(Entity.table_ref())
            .if_not_exists()
            .col(ColumnDef::new(Column::Id).not_null().string().primary_key())
            // Specific
            .col(ColumnDef::new(Column::SysCode).not_null().string())
            .col(ColumnDef::new(Column::BusCode).not_null().string())
            .col(ColumnDef::new(Column::Name).not_null().string())
            .col(ColumnDef::new(Column::Icon).not_null().string())
            .col(ColumnDef::new(Column::Sort).not_null().unsigned())
            .col(ColumnDef::new(Column::Ext).not_null().string())
            .col(ColumnDef::new(Column::RelRbumSetId).not_null().string())
            // Basic
            .col(ColumnDef::new(Column::OwnPaths).not_null().string())
            .col(ColumnDef::new(Column::Owner).not_null().string())
            .col(ColumnDef::new(Column::CreateTime).extra("DEFAULT CURRENT_TIMESTAMP".to_string()).date_time())
            .col(ColumnDef::new(Column::UpdateTime).extra("DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP".to_string()).date_time())
            // With Scope
            .col(ColumnDef::new(Column::ScopeLevel).not_null().tiny_integer())
            .to_owned()
    }

    fn create_index_statement() -> Vec<IndexCreateStatement> {
        vec![
            Index::create()
                .name(&format!("idx-{}-{}-{}", Entity.table_name(), Column::RelRbumSetId.to_string(), Column::SysCode.to_string()))
                .table(Entity)
                .col(Column::RelRbumSetId)
                .col(Column::SysCode)
                .unique()
                .to_owned(),
            Index::create()
                .name(&format!("idx-{}-{}-{}", Entity.table_name(), Column::RelRbumSetId.to_string(), Column::BusCode.to_string()))
                .table(Entity)
                .col(Column::RelRbumSetId)
                .col(Column::BusCode)
                .to_owned(),
        ]
    }
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
