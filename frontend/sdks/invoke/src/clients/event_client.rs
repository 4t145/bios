use std::{
    collections::HashMap,
    future::Future,
    iter,
    pin::Pin,
    sync::{Arc, OnceLock},
    time::Duration,
};

use crossbeam::sync::ShardedLock;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tardis::{
    basic::{dto::TardisContext, error::TardisError, result::TardisResult},
    log::warn,
    serde_json, tokio,
    web::{
        poem_openapi::{self, Object},
        tokio_tungstenite::tungstenite::Message,
        web_resp::{TardisResp, Void},
        ws_client::TardisWSClient,
        ws_processor::{TardisWebsocketMessage, TardisWebsocketReq},
    },
    TardisFuns, TardisFunsInst,
};

#[derive(Clone)]
pub struct EventClient<'a> {
    pub funs: &'a TardisFunsInst,
    pub base_url: &'a str,
}

impl<'a> EventClient<'a> {
    pub fn new(url: &'a str, funs: &'a TardisFunsInst) -> Self {
        Self { base_url: url, funs }
    }

    pub async fn register(&self, req: &EventListenerRegisterReq) -> TardisResult<EventListenerRegisterResp> {
        let url = format!("{}/listener", self.base_url.trim_end_matches('/'));

        let resp = self.funs.web_client().post::<EventListenerRegisterReq, TardisResp<EventListenerRegisterResp>>(&url, req, iter::empty()).await?;
        if let Some(resp) = resp.body {
            if let Some(data) = resp.data {
                return Ok(data);
            } else {
                return Err(self.funs.err().internal_error("event", "register", &resp.msg, ""));
            }
        }
        return Err(self.funs.err().internal_error("event", "register", "failed to register event listener", ""));
    }

    pub async fn remove(&self, listener_code: &str, token: &str) -> TardisResult<()> {
        let url = format!("{}/listener/{}?token={}", self.base_url.trim_end_matches('/'), listener_code, token);
        let resp = self.funs.web_client().delete::<TardisResp<Void>>(&url, iter::empty()).await?;
        if let Some(resp) = resp.body {
            if resp.data.is_some() {
                return Ok(());
            } else {
                return Err(self.funs.err().internal_error("event", "register", &resp.msg, ""));
            }
        }
        return Err(self.funs.err().internal_error("event", "register", "failed to register event listener", ""));
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EventListenerRegisterReq {
    // #[oai(validator(pattern = r"^[a-z0-9]+$"))]
    pub topic_code: String,
    pub topic_sk: Option<String>,
    // #[oai(validator(pattern = r"^[a-z0-9-_]+$"))]
    pub events: Option<Vec<String>>,
    pub avatars: Vec<String>,
    pub subscribe_mode: bool,
}

#[derive(Serialize, Deserialize, Debug, Object)]
pub struct EventListenerRegisterResp {
    pub ws_addr: String,
    pub listener_code: String,
}

// GLOBAL EVENT BUS
pub const TOPIC_EVENT_BUS: &str = "event_bus";

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
#[serde(default)]
pub struct EventTopicConfig {
    pub topic_code: String,
    pub topic_sk: Option<String>,
    pub events: Option<Vec<String>>,
    pub avatars: Vec<String>,
    pub subscribe_mode: bool,
    pub base_url: String,
    pub in_event: bool,
}

impl From<EventTopicConfig> for EventListenerRegisterReq {
    fn from(val: EventTopicConfig) -> Self {
        EventListenerRegisterReq {
            topic_code: val.topic_code,
            topic_sk: val.topic_sk,
            events: val.events,
            avatars: val.avatars,
            subscribe_mode: val.subscribe_mode,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ContextEvent<T> {
    pub ctx: TardisContext,
    pub event: T,
}

impl<T> ContextEvent<T> {
    #[inline(always)]
    pub fn unpack(self) -> (TardisContext, T) {
        (self.ctx, self.event)
    }
}
pub trait Event: Serialize + DeserializeOwned {
    const CODE: &'static str;
}

pub trait EventCenter {
    fn init(&self) -> TardisResult<()>;
    fn publish<E: Event>(&self, source: impl Into<String>, payload: E) -> impl Future<Output = TardisResult<()>>;
    fn subscribe<E: Event, H: EventHandler<E>>(&self, handler: H);
}

impl<T> EventCenter for Arc<T>
where
    T: EventCenter,
{
    fn init(&self) -> TardisResult<()> {
        T::init(self)
    }

    fn publish<E: Event>(&self, source: impl Into<String>, payload: E) -> impl Future<Output = TardisResult<()>> {
        self.as_ref().publish(source, payload)
    }

    fn subscribe<E: Event, H: EventHandler<E>>(&self, handler: H) {
        self.as_ref().subscribe(handler)
    }
}
#[derive(Debug, Clone, Default)]
pub struct BiosEventCenter {
    inner: WsEventCenter,
}

impl BiosEventCenter {
    pub fn new() -> Self {
        Self { inner: WsEventCenter::default() }
    }
}

impl EventCenter for BiosEventCenter {
    fn init(&self) -> TardisResult<()> {
        self.inner.init()
    }
    async fn publish<E: Event>(&self, source: impl Into<String>, payload: E) -> TardisResult<()> {
        self.inner.publish(source, payload).await
    }

    fn subscribe<E: Event, H: EventHandler<E>>(&self, handler: H) {
        self.inner.subscribe(handler);
    }
}

pub trait EventHandler<E>: Clone + Sync + Send + 'static {
    fn handle(self, event: E) -> impl Future<Output = TardisResult<()>> + Send;
}
#[derive(Debug, Clone)]
pub struct FnEventHandler<F>(pub F);
impl<E, F, Fut> EventHandler<E> for FnEventHandler<F>
where
    F: Fn(E) -> Fut + Send + Sync + Clone + 'static,
    Fut: Future<Output = TardisResult<()>> + Send,
{
    fn handle(self, event: E) -> impl Future<Output = TardisResult<()>> + Send {
        (self.0.clone())(event)
    }
}

type WsEventCenterHandler = dyn Fn(serde_json::Value) -> Pin<Box<dyn Future<Output = TardisResult<()>> + Send>> + Send + Sync;
type WsHandlersMap = HashMap<&'static str, Vec<Arc<WsEventCenterHandler>>>;
#[derive(Clone, Default)]
struct WsEventCenter {
    handlers: Arc<ShardedLock<WsHandlersMap>>,
    ws_client: OnceLock<TardisWSClient>,
}

impl std::fmt::Debug for WsEventCenter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let handlers_key = self.handlers.read().expect("should never be poisoned").iter().map(|(k, v)| (*k, v.len())).collect::<HashMap<&'static str, usize>>();
        f.debug_struct("WsEventCenter").field("handlers", &handlers_key).field("ws_client", &self.ws_client).finish()
    }
}

const EVENT_CENTER_MODULE: &str = "ws-event-center";

#[derive(Debug, Serialize, Deserialize)]
pub struct WsEventCenterConfig {
    base_url: String,
    topic_sk: String,
    avatars: Vec<String>,
}
impl EventCenter for WsEventCenter {
    fn init(&self) -> TardisResult<()> {
        let this = self.clone();
        const RETRY_INTERVAL: Duration = Duration::from_secs(1);
        tokio::spawn(async move {
            let config = TardisFuns::cs_config::<WsEventCenterConfig>(EVENT_CENTER_MODULE);
            let url = config.base_url.as_str();
            let funs = TardisFuns::inst("", None);

            let client = EventClient::new(url, &funs);
            // wait for web server to start
            loop {
                if TardisFuns::web_server().is_running().await {
                    break;
                } else {
                    tokio::task::yield_now().await
                }
            }
            let resp = client
                .register(&EventListenerRegisterReq {
                    topic_code: TOPIC_EVENT_BUS.to_string(),
                    topic_sk: Some(config.topic_sk.clone()),
                    events: None,
                    avatars: config.avatars.clone(),
                    subscribe_mode: true,
                })
                .await
                .expect("fail to register event center");
            let ws_client = loop {
                let ws_client = {
                    let this = this.clone();
                    TardisFuns::ws_client(&resp.ws_addr, move |message| {
                        let this = this.clone();
                        async move {
                            let Message::Text(text) = message else { return None };
                            let Ok(TardisWebsocketMessage { msg, event, .. }) = TardisFuns::json.str_to_obj(&text) else {
                                return None;
                            };
                            if let Some(evt) = event {
                                let evt: Arc<str> = Arc::from(evt);
                                let handlers = { this.handlers.read().expect("never poisoned").get(evt.as_ref()).cloned().unwrap_or_default() };
                                for h in handlers {
                                    let evt = evt.clone();
                                    let msg = msg.clone();
                                    tokio::spawn(async move {
                                        let result = (h)(msg.clone()).await;
                                        if let Err(e) = result {
                                            warn!("encounter an error when processing event [{evt}]: {e}");
                                        }
                                    });
                                }
                            }
                            None
                        }
                    })
                    .await
                };
                match ws_client {
                    Ok(ws_client) => break ws_client,
                    Err(e) => {
                        warn!("fail to connect event center {e}");
                        tokio::time::sleep(RETRY_INTERVAL).await;
                        continue;
                    }
                }
            };
            this.ws_client.get_or_init(|| ws_client);
            loop {
                if let Err(e) = this.ws_client.get().expect("should be initialized").reconnect().await {
                    warn!("ws client fails to reconnect server {e}");
                    tokio::time::sleep(RETRY_INTERVAL).await;
                }
            }
        });
        Ok(())
    }
    async fn publish<E: Event>(&self, source: impl Into<String>, payload: E) -> TardisResult<()> {
        let code = E::CODE;
        if let Some(client) = self.ws_client.get() {
            client
                .send_obj(&TardisWebsocketReq {
                    msg: TardisFuns::json.obj_to_json(&payload)?,
                    from_avatar: source.into(),
                    to_avatars: code.split_once('/').map(|(service, _)| vec![service.to_string()]),
                    event: Some(E::CODE.to_string()),
                    ..Default::default()
                })
                .await
        } else {
            Err(TardisError::internal_error("event center not initialized", ""))
        }
    }

    fn subscribe<E: Event, H: EventHandler<E>>(&self, handler: H) {
        let wrapped_handler: Arc<WsEventCenterHandler> = Arc::new(move |value: serde_json::Value| {
            let handler = handler.clone();
            Box::pin(async move {
                let event: E = serde_json::from_value(value).map_err(|e| TardisError::internal_error(&format!("can't deserialize event message: {e}"), ""))?;
                handler.handle(event).await
            })
        });
        let key = E::CODE;
        self.handlers.write().expect("never poisoned").entry(key).or_default().push(wrapped_handler);
    }
}
