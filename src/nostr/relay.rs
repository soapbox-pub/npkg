//! One-shot queries: connect to each relay, ask, collect what it has until it
//! says it's done, hang up.
//!
//! A repository is rebuilt every few minutes at most, so there is nothing to
//! gain yet from holding connections open between builds.

use std::collections::HashMap;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::time::timeout_at;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use super::Event;

/// The largest message taken from a relay.
const MAX_MESSAGE: usize = 4 << 20;

/// The most events taken from one relay for one query. NIP-82 events are
/// small, and a repository has tens of releases, not thousands.
const MAX_EVENTS: usize = 5_000;

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

async fn query_one(relay: &str, filters: &[Value]) -> anyhow::Result<Vec<Event>> {
    let config = WebSocketConfig::default().max_message_size(Some(MAX_MESSAGE)).max_frame_size(Some(MAX_MESSAGE));
    let (mut socket, _) = tokio_tungstenite::connect_async_with_config(relay, Some(config), false).await?;

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
