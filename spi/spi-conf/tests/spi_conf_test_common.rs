use bios_basic::{
    rbum::{rbum_config::RbumConfig, rbum_initializer},
    test::test_http_client::TestHttpClient,
};
use bios_spi_conf::{conf_constants::DOMAIN_CODE, conf_initializer};
use tardis::testcontainers::images::{generic::GenericImage, redis::Redis};
use tardis::{
    basic::{dto::TardisContext, result::TardisResult},
    test::test_container::TardisTestContainer,
    testcontainers::{clients::Cli, Container},
    tokio::{self, task::JoinHandle},
    TardisFuns,
};
pub struct Holder<'d> {
    pub pg: Container<'d, GenericImage>,
    pub redis: Container<'d, Redis>,
}
#[allow(dead_code)]
pub async fn init_tardis(docker: &Cli) -> TardisResult<Holder> {
    let reldb_container = TardisTestContainer::postgres_custom(None, docker);
    let port = reldb_container.get_host_port_ipv4(5432);
    let url = format!("postgres://postgres:123456@localhost:{port}/test");
    std::env::set_var("TARDIS_FW.DB.URL", url);
    let redis_container = TardisTestContainer::redis_custom(docker);
    let port = redis_container.get_host_port_ipv4(6379);
    let url = format!("redis://127.0.0.1:{port}/0");
    std::env::set_var("TARDIS_FW.CACHE.URL", url);
    let holder = Holder {
        pg: reldb_container,
        redis: redis_container,
    };
    TardisFuns::init(Some("tests/config")).await?;
    bios_basic::rbum::rbum_initializer::init(DOMAIN_CODE, RbumConfig::default()).await?;
    let web_server = TardisFuns::web_server();
    rbum_initializer::init("bios-spi", RbumConfig::default()).await?;
    conf_initializer::init(web_server).await?;
    Ok(holder)
}

#[allow(dead_code)]
pub fn start_web_server() -> JoinHandle<TardisResult<()>> {
    let task = TardisFuns::web_server().start();
    tokio::spawn(task)
}

#[allow(dead_code)]
pub fn get_client(url: &str, ctx: &TardisContext) -> TestHttpClient {
    let mut client: TestHttpClient = TestHttpClient::new(url.into());
    client.set_auth(ctx).unwrap();
    client
}
