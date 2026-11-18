//! `POST /hooks/eventgrid`: expiry events pushed by Event Grid.
//!
//! The one route that takes a request with no session. In order, before
//! anything is read from the body:
//!
//! 1. 404 unless email is on and `KEYRING_NOTIFY_TYPES` has `expiry`.
//! 2. 405 unless POST.
//! 3. The bearer token, checked by [`crate::auth::eventgrid`] with no body
//!    read. A token that fails takes one from the unauthenticated counter
//!    ([`HookTuning::unauth_per_minute`]): under it, 401 with no body and
//!    an audit event; over it, 429 with no audit event (a `warn` line,
//!    written by the first bad token of a later window, gives how many
//!    were dropped; the request log still has its one line per request,
//!    as on every route). Either way the authenticated budget is
//!    untouched.
//! 4. 429 past the authenticated budget ([`HookTuning::per_minute`]),
//!    taken only by deliveries whose token passed.
//! 5. 415 unless `Content-Type` is `application/json`.
//! 6. 413 if `Content-Length` says more than 1 MB; the body is then read
//!    with the same limit.
//!
//! Then the delivery is parsed, all or nothing (400 on anything
//! malformed, an event whose `topic` isn't its Key Vault, or, with
//! `KEYRING_EVENTGRID_SUBSCRIPTIONS` set, a vault in a subscription not in
//! that list), before any dedupe or email work. Then the
//! handshake is answered, or each event is deduplicated and queued. 200
//! once every event is queued, a repeat, or has no allowed recipient. 503
//! when the email queue or the dedupe map is full, or when every
//! recipient is over the per-recipient rate limit, so Event Grid retries
//! (its 24 hours of retries cover the one-hour rate window). Events
//! already queued in that delivery stay remembered, so the retry skips
//! them. An email that reached some recipients and left out others over
//! their limit counts as sent and isn't retried, or the others would get
//! it twice.
//!
//! Logged: a fixed reason code and counts. Never the token, its claims,
//! the body, the `topic`, headers or an address. One `notify.webhook`
//! audit event per request that reached the token check, except those
//! over the unauthenticated counter.
//!
//! [`HookTuning::unauth_per_minute`]: crate::notify::expiry::HookTuning::unauth_per_minute
//! [`HookTuning::per_minute`]: crate::notify::expiry::HookTuning::per_minute

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::AppState;
use crate::audit::{self, Action, Outcome};
use crate::auth::eventgrid;
use crate::notify::expiry::{
    self, Delivery, ExpiryNotice, MAX_BODY_BYTES, MAX_HEADER_RECIPIENTS, RECIPIENT_HEADER, Seen,
    Unauth,
};
use crate::notify::{Address, Enqueued, Notification, NotifyType};

fn status(code: StatusCode) -> Response {
    (code, [(header::CACHE_CONTROL, "no-store")]).into_response()
}

/// End the delivery's audit event and log the code. `count` is how many
/// events the delivery held, when known.
fn finish(outcome: Outcome, code: &str, count: Option<usize>) {
    audit::note_notify(NotifyType::Expiry.as_str(), count.map(|n| n as u64));
    audit::end(outcome, code);
    tracing::info!(result = code, events = count, "eventgrid: delivery");
}

fn is_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/json"))
}

/// Who gets the delivery's emails: the `keyring-notify` header's addresses
/// when `KEYRING_NOTIFY_ALLOWED_DOMAINS` is set, otherwise the admins.
/// `Err` for a header that is there but malformed or too long.
fn recipients(
    headers: &HeaderMap,
    allow_header: bool,
    admins: &[Address],
) -> Result<Vec<Address>, ()> {
    if !allow_header {
        return Ok(admins.to_vec());
    }
    let mut values = headers.get_all(RECIPIENT_HEADER).iter();
    let Some(v) = values.next() else {
        return Ok(admins.to_vec());
    };
    if values.next().is_some() {
        return Err(());
    }
    let raw = v.to_str().map_err(|_| ())?;
    crate::notify::parse_addresses(raw, MAX_HEADER_RECIPIENTS).map_err(|_| ())
}

pub(super) async fn eventgrid(State(state): State<AppState>, req: Request) -> Response {
    let (Some(hook), Some(notifier)) = (state.expiry_hook.as_deref(), state.notifier.as_deref())
    else {
        return status(StatusCode::NOT_FOUND);
    };
    if !notifier.is_on(NotifyType::Expiry) {
        return status(StatusCode::NOT_FOUND);
    }
    if req.method() != Method::POST {
        return status(StatusCode::METHOD_NOT_ALLOWED);
    }

    // The token, before anything else is read or counted.
    let auth = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let checked = match eventgrid::bearer(auth) {
        Ok(token) => {
            eventgrid::verify(
                token,
                &hook.expect,
                &state.oidc,
                eventgrid::now_unix(),
                || hook.may_refetch(),
            )
            .await
        }
        Err(e) => Err(e),
    };
    if let Err(why) = checked {
        // Its own counter, so a flood of bad tokens can't use up Event
        // Grid's budget. Over it: no audit event.
        if hook.take_unauth() == Unauth::Dropped {
            return status(StatusCode::TOO_MANY_REQUESTS);
        }
        audit::set_action(Action::NotifyWebhook);
        finish(Outcome::Refused, why.as_str(), None);
        return (
            StatusCode::UNAUTHORIZED,
            [
                (header::WWW_AUTHENTICATE, "Bearer"),
                (header::CACHE_CONTROL, "no-store"),
            ],
        )
            .into_response();
    }
    audit::set_action(Action::NotifyWebhook);
    if !hook.take_rate() {
        finish(Outcome::Refused, "rate_limited", None);
        return status(StatusCode::TOO_MANY_REQUESTS);
    }

    if !is_json(req.headers()) {
        finish(Outcome::Refused, "not_json", None);
        return status(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let too_long = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|n| n > MAX_BODY_BYTES as u64);
    if too_long {
        finish(Outcome::Refused, "too_large", None);
        return status(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let allow_header = state
        .config
        .notify
        .as_ref()
        .is_some_and(|n| n.allowed_domains.is_some());
    let to = recipients(req.headers(), allow_header, notifier.admins());
    let body: Body = req.into_body();
    let Ok(bytes) = axum::body::to_bytes(body, MAX_BODY_BYTES).await else {
        finish(Outcome::Refused, "too_large", None);
        return status(StatusCode::PAYLOAD_TOO_LARGE);
    };

    let events = match expiry::parse_delivery(&bytes, hook.subscriptions.as_deref()) {
        Ok(Delivery::Validation(code)) => {
            finish(Outcome::Success, "validation", Some(1));
            let body = serde_json::json!({ "validationResponse": code }).to_string();
            return (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/json"),
                    (header::CACHE_CONTROL, "no-store"),
                ],
                body,
            )
                .into_response();
        }
        Ok(Delivery::Events(e)) => e,
        Err(why) => {
            finish(Outcome::Refused, why.as_str(), None);
            return status(StatusCode::BAD_REQUEST);
        }
    };
    let Ok(to) = to else {
        finish(Outcome::Refused, "bad_recipients", Some(events.len()));
        return status(StatusCode::BAD_REQUEST);
    };

    let now = eventgrid::now_unix();
    let mut busy = false;
    let mut limited = false;
    let mut queued = 0usize;
    let mut no_recipients = 0usize;
    for e in &events {
        if busy || limited {
            break;
        }
        match hook.reserve(e) {
            Seen::Repeat => continue,
            Seen::Full => {
                busy = true;
                continue;
            }
            Seen::New => {}
        }
        let n = Notification {
            kind: NotifyType::Expiry,
            to: to.clone(),
            item: Some(e.item.clone()),
            data: ExpiryNotice::new(e, now, &hook.base_url),
        };
        match notifier.enqueue(n) {
            Enqueued::Queued { .. } => queued += 1,
            Enqueued::QueueFull => {
                // Forget it, so Event Grid's retry sends it. Events
                // already queued stay remembered, so the retry skips them.
                hook.release(e);
                busy = true;
            }
            Enqueued::RateLimited => {
                // Every recipient is over the per-recipient limit for the
                // hour: the same as a full queue, so a later retry sends.
                hook.release(e);
                limited = true;
            }
            // Nobody allowed to send to, or a body that can't be sent:
            // nothing a retry would change, so it stays remembered.
            Enqueued::NoRecipients | Enqueued::Invalid | Enqueued::Off => no_recipients += 1,
        }
    }
    if busy {
        finish(Outcome::Failed, "queue_full", Some(events.len()));
        return status(StatusCode::SERVICE_UNAVAILABLE);
    }
    if limited {
        finish(
            Outcome::Failed,
            "recipient_rate_limited",
            Some(events.len()),
        );
        return status(StatusCode::SERVICE_UNAVAILABLE);
    }
    let code = if no_recipients > 0 {
        "no_recipients"
    } else if queued == 0 {
        "repeat"
    } else {
        "queued"
    };
    finish(Outcome::Success, code, Some(events.len()));
    status(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    #[test]
    fn json_only() {
        let mut h = HeaderMap::new();
        assert!(!is_json(&h));
        for ok in ["application/json", "Application/JSON; charset=utf-8"] {
            h.insert(header::CONTENT_TYPE, HeaderValue::from_static(ok));
            assert!(is_json(&h), "{ok}");
        }
        for bad in [
            "text/plain",
            "application/cloudevents-batch+json",
            "application/jsonx",
        ] {
            h.insert(header::CONTENT_TYPE, HeaderValue::from_static(bad));
            assert!(!is_json(&h), "{bad}");
        }
    }

    #[test]
    fn the_header_is_used_only_with_an_allow_list() {
        let admins = vec![Address::parse("ops@example.com").unwrap()];
        let mut h = HeaderMap::new();
        h.insert(
            RECIPIENT_HEADER,
            HeaderValue::from_static("team@example.com"),
        );
        assert_eq!(recipients(&h, false, &admins).unwrap(), admins);
        assert_eq!(
            recipients(&h, true, &admins).unwrap(),
            vec![Address::parse("team@example.com").unwrap()]
        );
        assert_eq!(
            recipients(&HeaderMap::new(), true, &admins).unwrap(),
            admins
        );
        for bad in [
            "Team <team@example.com>",
            "team@example.com,,b@example.com",
            "a@x.com,b@x.com,c@x.com,d@x.com,e@x.com,f@x.com,g@x.com,h@x.com,i@x.com,j@x.com,k@x.com",
        ] {
            let mut h = HeaderMap::new();
            h.insert(RECIPIENT_HEADER, HeaderValue::from_static(bad));
            assert!(recipients(&h, true, &admins).is_err(), "{bad}");
        }
        let mut h = HeaderMap::new();
        h.append(RECIPIENT_HEADER, HeaderValue::from_static("a@example.com"));
        h.append(RECIPIENT_HEADER, HeaderValue::from_static("b@example.com"));
        assert!(recipients(&h, true, &admins).is_err());
    }
}
