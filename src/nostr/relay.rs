//! Talking to relays: one-shot queries, which ask every relay, collect what
//! each has until it says it's done, and hang up; and subscriptions, which
//! stay connected and pass on new events as they arrive.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio::time::{Instant, timeout, timeout_at};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use super::Event;

/// The largest message taken from a relay.
const MAX_MESSAGE: usize = 4 << 20;

/// The most events taken from one relay for one query. NIP-82 events are
/// small, and a repository has tens of releases, not thousands.
const MAX_EVENTS: usize = 5_000;

/// How long connecting to a relay may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How often a subscription pings its relay, and how long it waits to hear
/// anything back before taking the connection for dead.
const PING_EVERY: Duration = Duration::from_secs(60);
const SILENCE: Duration = Duration::from_secs(180);

/// The wait before reconnecting to a relay: doubled after each failure, up to
/// the most, and back to the least once a connection has lasted.
const MIN_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(300);
const LASTED: Duration = Duration::from_secs(60);

/// How far before a dropped connection was made a reconnection asks from, for
/// events whose authors' clocks run a little behind.
const SINCE_MARGIN: i64 = 120;

/// Every event any of `relays` has for `filters`, verified, each once.
/// Relays that fail or don't answer in `timeout` are skipped: the answer is
/// what the rest had. An error only when none answered, so that an outage
/// isn't mistaken for an author having published nothing.
pub async fn query(relays: &[String], filters: &[Value], timeout: Duration) -> anyhow::Result<Vec<Event>> {
    let deadline = tokio::time::Instant::now() + timeout;
    let queries = relays.iter().map(|relay| async move {
        match timeout_at(deadline, query_one(relay, filters)).await {
            Ok(Ok(events)) => Some(events),
            Ok(Err(error)) => {
                tracing::debug!(relay, %error, "relay query failed");
                None
            }
            Err(_) => {
                tracing::debug!(relay, "relay query timed out");
                None
            }
        }
    });

    let mut seen = HashMap::new();
    let mut answered = false;
    for events in futures_util::future::join_all(queries).await.into_iter().flatten() {
        answered = true;
        for event in events {
            seen.entry(event.id.clone()).or_insert(event);
        }
    }
    anyhow::ensure!(answered, "No relay answered. Check the gateway's relays and its network.");
    Ok(seen.into_values().filter(Event::verify).collect())
}

async fn connect(relay: &str) -> anyhow::Result<Socket> {
    let config = WebSocketConfig::default().max_message_size(Some(MAX_MESSAGE)).max_frame_size(Some(MAX_MESSAGE));
    let connecting = tokio_tungstenite::connect_async_with_config(relay, Some(config), false);
    let (socket, _) = timeout(CONNECT_TIMEOUT, connecting).await.map_err(|_| anyhow::anyhow!("{relay} didn't answer in time."))??;
    Ok(socket)
}

type Socket = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn query_one(relay: &str, filters: &[Value]) -> anyhow::Result<Vec<Event>> {
    let mut socket = connect(relay).await?;

    let mut request = vec![json!("REQ"), json!("q")];
    request.extend(filters.iter().cloned());
    socket.send(Message::text(Value::Array(request).to_string())).await?;

    let mut events = Vec::new();
    while let Some(message) = socket.next().await {
        let Message::Text(text) = message? else { continue };
        let Ok(Value::Array(parts)) = serde_json::from_str::<Value>(&text) else { continue };
        match parts.first().and_then(Value::as_str) {
            Some("EVENT") if parts.get(1).and_then(Value::as_str) == Some("q") => {
                if let Some(Ok(event)) = parts.get(2).map(|event| serde_json::from_value::<Event>(event.clone())) {
                    events.push(event);
                }
                if events.len() >= MAX_EVENTS {
                    break;
                }
            }
            Some("EOSE") | Some("CLOSED") => break,
            _ => {}
        }
    }

    let _ = socket.send(Message::text(json!(["CLOSE", "q"]).to_string())).await;
    let _ = socket.close(None).await;
    Ok(events)
}

/// Every event matching `filters` that any of `relays` gets from now on,
/// verified, as it arrives; an event more than one relay sends comes more
/// than once. Each relay is reconnected when its connection drops, asking
/// again from shortly before that connection was made, so a dropped
/// connection loses nothing. It ends once the receiver is dropped.
pub fn subscribe(relays: &[String], filters: Vec<Value>) -> mpsc::Receiver<Event> {
    let (sender, receiver) = mpsc::channel(1024);
    for relay in relays {
        tokio::spawn(follow(relay.clone(), filters.clone(), sender.clone()));
    }
    receiver
}

async fn follow(relay: String, filters: Vec<Value>, sender: mpsc::Sender<Event>) {
    let mut since = unix_now();
    let mut backoff = MIN_BACKOFF;
    loop {
        let started = (Instant::now(), unix_now());
        let mut connected = false;
        let result = follow_once(&relay, &filters, since, &sender, &mut connected).await;
        if sender.is_closed() {
            return;
        }
        match result {
            Ok(()) => tracing::debug!(relay, "relay hung up"),
            Err(error) => tracing::debug!(relay, %error, "subscription failed"),
        }
        if connected {
            since = started.1 - SINCE_MARGIN;
        }
        if started.0.elapsed() >= LASTED {
            backoff = MIN_BACKOFF;
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

async fn follow_once(relay: &str, filters: &[Value], since: i64, sender: &mpsc::Sender<Event>, connected: &mut bool) -> anyhow::Result<()> {
    let mut socket = connect(relay).await?;
    *connected = true;
    tracing::debug!(relay, since, "subscribed");

    let mut request = vec![json!("REQ"), json!("live")];
    request.extend(filters.iter().map(|filter| {
        let mut filter = filter.clone();
        filter["since"] = json!(since);
        filter
    }));
    socket.send(Message::text(Value::Array(request).to_string())).await?;

    let mut ping = tokio::time::interval_at(Instant::now() + PING_EVERY, PING_EVERY);
    let mut heard = Instant::now();
    loop {
        tokio::select! {
            message = socket.next() => {
                let Some(message) = message else { return Ok(()) };
                heard = Instant::now();
                let Message::Text(text) = message? else { continue };
                let Ok(Value::Array(parts)) = serde_json::from_str::<Value>(&text) else { continue };
                match parts.first().and_then(Value::as_str) {
                    Some("EVENT") if parts.get(1).and_then(Value::as_str) == Some("live") => {
                        let Some(Ok(event)) = parts.get(2).map(|event| serde_json::from_value::<Event>(event.clone())) else { continue };
                        if event.verify() && sender.send(event).await.is_err() {
                            return Ok(());
                        }
                    }
                    Some("CLOSED") => {
                        let reason = parts.get(2).and_then(Value::as_str).unwrap_or_default();
                        anyhow::bail!("{relay} closed the subscription: {reason}");
                    }
                    _ => {}
                }
            }
            _ = ping.tick() => {
                anyhow::ensure!(heard.elapsed() < SILENCE, "{relay} went quiet.");
                socket.send(Message::Ping(Default::default())).await?;
            }
            _ = sender.closed() => return Ok(()),
        }
    }
}

fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.as_secs() as i64)
}
