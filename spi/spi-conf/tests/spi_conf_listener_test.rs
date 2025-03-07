use std::{
    env,
    sync::{atomic::AtomicUsize, Arc},
};

use bios_basic::{
    rbum::serv::rbum_kind_serv::RbumKindServ,
    spi::{dto::spi_bs_dto::SpiBsAddReq, spi_constants},
    test::test_http_client::TestHttpClient,
};
use bios_spi_conf::{conf_constants::DOMAIN_CODE, dto::conf_config_dto::ConfigDescriptor};
use tardis::{
    basic::{dto::TardisContext, field::TrimString, result::TardisResult},
    log::debug,
    rand,
    serde_json::json,
    testcontainers, tokio,
    web::web_resp::Void,
    TardisFuns,
};
mod spi_conf_test_common;
use spi_conf_test_common::*;

#[tokio::test]
async fn spi_conf_namespace_test() -> TardisResult<()> {
    std::env::set_var("RUST_LOG", "error,spi_conf_listener_test=debug,sqlx=off,sea_orm=off,bios_spi_conf=DEBUG");
    let docker = testcontainers::clients::Cli::default();
    let container_hold = init_tardis(&docker).await?;
    let _web_server_hanlde = start_web_server();
    let tardis_ctx = TardisContext::default();
    let mut client = TestHttpClient::new("https://localhost:8080/spi-conf".to_string());
    client.set_auth(&tardis_ctx)?;
    let funs = TardisFuns::inst_with_db_conn(DOMAIN_CODE.to_string(), None);
    let kind_id = RbumKindServ::get_rbum_kind_id_by_code(spi_constants::SPI_PG_KIND_CODE, &funs).await?.unwrap();
    let bs_id: String = client
        .post(
            "/ci/manage/bs",
            &SpiBsAddReq {
                name: TrimString("test-spi".to_string()),
                kind_id: TrimString(kind_id),
                conn_uri: env::var("TARDIS_FW.DB.URL").unwrap(),
                ak: TrimString("".to_string()),
                sk: TrimString("".to_string()),
                ext: "{\"max_connections\":20,\"min_connections\":10}".to_string(),
                private: false,
                disabled: None,
            },
        )
        .await;
    let _: Void = client.put(&format!("/ci/manage/bs/{}/rel/app001", bs_id), &Void {}).await;
    client.set_auth(&TardisContext {
        own_paths: "t1/app001".to_string(),
        ak: "".to_string(),
        roles: vec![],
        groups: vec![],
        owner: "app001".to_string(),
        ..Default::default()
    })?;
    test_single_listener(&mut client).await?;
    test_listener(&mut client).await?;
    // web_server_hanlde.await.unwrap()?;
    drop(container_hold);
    Ok(())
}

pub fn gen_random_config_content() -> String {
    let mut content = String::new();
    for _ in 0..64 {
        content.push_str(format!("{:08x}", rand::random::<u64>()).as_str());
    }
    content
}

pub async fn test_single_listener(client: &mut TestHttpClient) -> TardisResult<()> {
    const DATA_ID: &str = "conf-single";
    let _response = client
        .post::<_, bool>(
            "/ci/cs/config",
            &json!( {
                "content": gen_random_config_content(),
                "group": "DEFAULT-GROUP".to_string(),
                "data_id": DATA_ID,
                "schema": "toml",
            }),
        )
        .await;
    let config = client.get::<String>(&format!("/ci/cs/config?group=DEFAULT-GROUP&data_id={DATA_ID}")).await;
    use tardis::crypto::rust_crypto::{digest::Digest, md5::Md5};
    let mut md5_encoder = Md5::new();
    md5_encoder.input_str(config.as_str());
    let md5 = md5_encoder.result_str();
    md5_encoder.reset();
    let config = client.get_resp::<ConfigDescriptor>(&format!("/ci/cs/configs/listener?data_id={DATA_ID}&group=DEFAULT-GROUP&md5={md5}")).await;
    // with a correct md5, no config should be returned
    assert!(config.data.is_none());
    // now update
    let _response = client
        .post::<_, bool>(
            "/ci/cs/config",
            &json!( {
                "content": gen_random_config_content(),
                "group": "DEFAULT-GROUP".to_string(),
                "data_id": DATA_ID,
                "schema": "toml",
            }),
        )
        .await;
    // check update again
    let config = client.get_resp::<ConfigDescriptor>(&format!("/ci/cs/configs/listener?data_id={DATA_ID}&group=DEFAULT-GROUP&md5={md5}")).await;
    // with a incorrect md5, config should be returned
    assert!(config.data.is_some());
    // get new config
    let config = client.get::<String>(&format!("/ci/cs/config?group=DEFAULT-GROUP&data_id={DATA_ID}")).await;
    md5_encoder.input_str(config.as_str());
    let md5 = md5_encoder.result_str();
    md5_encoder.reset();
    // check update again
    let config = client.get_resp::<ConfigDescriptor>(&format!("/ci/cs/configs/listener?data_id={DATA_ID}&group=DEFAULT-GROUP&md5={md5}")).await;
    // with a correct md5, no config should be returned
    assert!(config.data.is_none());
    Ok(())
}

pub async fn test_listener(client: &mut TestHttpClient) -> TardisResult<()> {
    let update_counter = Arc::new(AtomicUsize::new(0));
    let ctx_raw = Arc::new(TardisContext {
        own_paths: "t1/app001".to_string(),
        ak: "".to_string(),
        roles: vec![],
        groups: vec![],
        owner: "app001".to_string(),
        ..Default::default()
    });
    let _response = client
        .post::<_, bool>(
            "/ci/cs/config",
            &json!( {
                "content": gen_random_config_content(),
                "group": "DEFAULT-GROUP".to_string(),
                "data_id": "conf-default".to_string(),
                "schema": "toml",
            }),
        )
        .await;
    let ctx = ctx_raw.clone();
    let updater = tokio::spawn(async move {
        let client = get_client("https://localhost:8080/spi-conf", &ctx);
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
        loop {
            let _response = client
                .post::<_, bool>(
                    "/ci/cs/config",
                    &json!( {
                        "content": gen_random_config_content(),
                        "group": "DEFAULT-GROUP".to_string(),
                        "data_id": "conf-default".to_string(),
                        "schema": "toml",
                    }),
                )
                .await;
            interval.tick().await;
        }
    });
    let mut join_set = tokio::task::JoinSet::new();
    const THREAD_NUM: usize = 500;
    for _ in 0..THREAD_NUM {
        let ctx = ctx_raw.clone();
        let update_counter = update_counter.clone();
        join_set.spawn(async move {
            let client = get_client("https://localhost:8080/spi-conf", &ctx);
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
            let mut md5 = String::new();
            use tardis::crypto::rust_crypto::{digest::Digest, md5::Md5};
            let mut md5_encoder = Md5::new();
            loop {
                let config = client.get_resp::<ConfigDescriptor>(&format!("/ci/cs/configs/listener?data_id=conf-default&group=DEFAULT-GROUP&md5={md5}")).await;
                if config.data.is_some() {
                    update_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let config = client.get::<String>("/ci/cs/config?group=DEFAULT-GROUP&data_id=conf-default").await;
                    md5_encoder.input_str(&config);
                    md5 = md5_encoder.result_str();
                    md5_encoder.reset();
                }
                interval.tick().await;
            }
        });
    }
    loop {
        let counter = update_counter.load(std::sync::atomic::Ordering::SeqCst);
        debug!("update_counter:{}", counter);
        if counter >= THREAD_NUM * 5 {
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
    join_set.abort_all();
    updater.abort();
    Ok(())
}
