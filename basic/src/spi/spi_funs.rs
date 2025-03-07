use async_trait::async_trait;
use std::any::Any;
use std::collections::HashMap;
use std::future::Future;
use std::ptr::replace;
use tardis::basic::dto::TardisContext;
use tardis::basic::error::TardisError;
use tardis::basic::result::TardisResult;
use tardis::log::info;
use tardis::TardisFuns;
use tardis::TardisFunsInst;

use crate::spi::dto::spi_bs_dto::SpiBsCertResp;

use super::serv::spi_bs_serv::SpiBsServ;
use super::spi_constants;

pub struct SpiBsInst {
    pub client: Box<dyn Any + Send + Sync>,
    pub ext: HashMap<String, String>,
}

pub type TypedSpiBsInst<'a, T> = (&'a T, &'a HashMap<String, String>, &'a str);

impl SpiBsInst {
    pub fn inst<T>(&self) -> TypedSpiBsInst<'_, T>
    // T is 'static meaning it's an owned type or only holds static references
    // dyn Any + Send + Sync ==downcast==> T: 'static + Send + Sync
    where
        T: 'static,
    {
        let c = self.client.as_ref().downcast_ref::<T>().unwrap();
        (c, &self.ext, self.kind_code())
    }

    pub fn kind_code(&self) -> &str {
        self.ext.get(spi_constants::SPI_KIND_CODE_FLAG).unwrap()
    }
}

static mut SPI_BS_CACHES: Option<HashMap<String, SpiBsInst>> = None;

#[async_trait]
pub trait SpiBsInstExtractor {
    async fn init<'a, F, T>(&self, ctx: &'a TardisContext, mgr: bool, init_funs: F) -> TardisResult<&SpiBsInst>
    where
        F: Fn(SpiBsCertResp, &'a TardisContext, bool) -> T + Send + Sync,
        T: Future<Output = TardisResult<SpiBsInst>> + Send;

    async fn bs<'a>(&self, ctx: &'a TardisContext) -> TardisResult<&'static SpiBsInst>;

    async fn init_bs<'a, F, T>(&self, ctx: &'a TardisContext, mgr: bool, init_funs: F) -> TardisResult<&'static SpiBsInst>
    where
        F: Fn(SpiBsCertResp, &'a TardisContext, bool) -> T + Send + Sync,
        T: Future<Output = TardisResult<SpiBsInst>> + Send;

    fn bs_not_implemented(&self, bs_code: &str) -> TardisError;
}

#[async_trait]
impl SpiBsInstExtractor for TardisFunsInst {
    /// Initialize the backend service instance
    ///
    /// # Arguments
    ///
    /// * `ctx` - Request Context
    /// * `mgr` - Whether it is a managed request
    /// * `init_fun` - The initialization function called when the backend service instance is not initialized
    ///
    /// # Return
    ///
    /// the backend service instance kind
    /// ```
    async fn init<'a, F, T>(&self, ctx: &'a TardisContext, mgr: bool, init_fun: F) -> TardisResult<&SpiBsInst>
    where
        F: Fn(SpiBsCertResp, &'a TardisContext, bool) -> T + Send + Sync,
        T: Future<Output = TardisResult<SpiBsInst>> + Send,
    {
        let cache_key = format!("{}-{}", self.module_code(), ctx.owner);
        unsafe {
            if SPI_BS_CACHES.is_none() {
                replace(&mut SPI_BS_CACHES, Some(HashMap::new()));
            }
            match &mut SPI_BS_CACHES {
                None => panic!("[SPI] CACHE instance doesn't exist"),
                Some(caches) => {
                    if !caches.contains_key(&cache_key) {
                        let spi_bs = SpiBsServ::get_bs_by_rel(&ctx.owner, None, self, ctx).await?;
                        info!(
                            "[SPI] Init and cache backend service instance [{}]:{}",
                            cache_key.clone(),
                            TardisFuns::json.obj_to_string(&spi_bs)?
                        );
                        let kind_code = spi_bs.kind_code.clone();
                        let mut spi_bs_inst = init_fun(spi_bs, ctx, mgr).await?;
                        spi_bs_inst.ext.insert(spi_constants::SPI_KIND_CODE_FLAG.to_string(), kind_code);
                        caches.insert(cache_key.clone(), spi_bs_inst);
                    }
                    Ok(caches.get(&cache_key).unwrap())
                }
            }
        }
    }

    /// Fetch the backend service instance
    ///
    /// # Arguments
    ///
    /// * `ctx` - Request Context
    ///
    /// # Return
    ///
    /// the backend service instance
    /// ```
    async fn bs<'a>(&self, ctx: &'a TardisContext) -> TardisResult<&'static SpiBsInst> {
        let cache_key = format!("{}-{}", self.module_code(), ctx.owner);
        unsafe {
            match &mut SPI_BS_CACHES {
                None => panic!("[SPI] CACHE instance doesn't exist"),
                Some(caches) => Ok(caches.get(&cache_key).unwrap()),
            }
        }
    }

    /// Initialize the backend service instance and fetch it
    ///
    /// # Arguments
    ///
    /// * `ctx` - Request Context
    /// * `mgr` - Whether it is a managed request
    /// * `init_fun` - The initialization function called when the backend service instance is not initialized
    ///
    /// # Return
    ///
    /// the backend service instance
    /// ```
    async fn init_bs<'a, F, T>(&self, ctx: &'a TardisContext, mgr: bool, init_fun: F) -> TardisResult<&'static SpiBsInst>
    where
        F: Fn(SpiBsCertResp, &'a TardisContext, bool) -> T + Send + Sync,
        T: Future<Output = TardisResult<SpiBsInst>> + Send,
    {
        self.init(ctx, mgr, init_fun).await?;
        self.bs(ctx).await
    }

    fn bs_not_implemented(&self, bs_code: &str) -> TardisError {
        bs_not_implemented(bs_code)
    }
}

pub fn bs_not_implemented(bs_code: &str) -> TardisError {
    TardisError::not_implemented(
        &format!("Backend service kind {bs_code} does not exist or SPI feature is not enabled"),
        "406-rbum-*-enum-init-error",
    )
}
