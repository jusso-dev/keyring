//! Event Grid's side of `/hooks/eventgrid`: bearer tokens shaped like the
//! ones Entra issues to Event Grid for a webhook secured with Microsoft
//! Entra ID, signed with the mock Entra's keys, and Key Vault expiry
//! deliveries in the Event Grid schema.
//!
//! Claims follow Microsoft's "Secure WebHook delivery with Microsoft Entra
//! ID" and the Microsoft identity platform's access token reference: an
//! app-only token (`roles`, no `scp`, `idtyp` `app`) whose `appid` (v1) or
//! `azp` (v2) is Event Grid's first-party application. A real tenant row
//! in docs/real-vault-checklist.md confirms what Event Grid really sends.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openidconnect::PrivateSigningKey;
use openidconnect::core::{CoreJwsSigningAlgorithm, CoreRsaPrivateSigningKey};
use serde_json::{Map, Value, json};

use super::{CLIENT_ID, MockIdp, TENANT};

/// Event Grid's first-party application ID.
pub(crate) const EVENT_GRID_APP: &str = "4962773b-9cdb-44cf-a8bf-237846a00ab7";
/// The app role Event Grid's service principal is given.
pub(crate) const ROLE: &str = "AzureEventGridSecureWebhookSubscriber";
pub(crate) const VERSION: &str = "0123456789abcdef0123456789abcdef";

pub(crate) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// The default audience, Keyring's app ID URI.
pub(crate) fn audience() -> String {
    format!("api://{CLIENT_ID}")
}

/// Claims of a good v1 token from Event Grid.
pub(crate) fn claims_v1(idp: &MockIdp) -> Map<String, Value> {
    json!({
        "aud": audience(),
        "iss": format!("{}/sts/{TENANT}/", idp.authority()),
        "iat": now() - 60,
        "nbf": now() - 60,
        "exp": now() + 3600,
        "appid": EVENT_GRID_APP,
        "appidacr": "2",
        "idp": format!("https://sts.windows.net/{TENANT}/"),
        "idtyp": "app",
        "oid": "99999999-0000-0000-0000-00000000e001",
        "sub": "99999999-0000-0000-0000-00000000e001",
        "roles": [ROLE],
        "tid": TENANT,
        "ver": "1.0",
    })
    .as_object()
    .unwrap()
    .clone()
}

/// Claims of a good v2 token from Event Grid.
pub(crate) fn claims_v2(idp: &MockIdp) -> Map<String, Value> {
    let mut c = claims_v1(idp);
    c.remove("appid");
    c.remove("appidacr");
    c.insert("azp".into(), json!(EVENT_GRID_APP));
    c.insert("azpacr".into(), json!("2"));
    c.insert(
        "iss".into(),
        json!(format!("{}/{TENANT}/v2.0", idp.authority())),
    );
    c.insert("ver".into(), json!("2.0"));
    c
}

/// Sign claims as the mock Entra does now (its rolled key when it has
/// rolled over), with header `alg` RS256 and the key's `kid`.
pub(crate) fn sign(idp: &MockIdp, claims: &Map<String, Value>) -> String {
    let rolled = *idp.state.rolled_over.lock().unwrap();
    let (key, kid) = if rolled {
        (&idp.state.other_key, "k2")
    } else {
        (&idp.state.key, "k1")
    };
    sign_with(
        key,
        json!({"alg": "RS256", "typ": "JWT", "kid": kid}),
        claims,
    )
}

/// Sign with a chosen key and header. The signature is RS256 whatever the
/// header says.
pub(crate) fn sign_with(
    key: &CoreRsaPrivateSigningKey,
    header: Value,
    claims: &Map<String, Value>,
) -> String {
    let h = URL_SAFE_NO_PAD.encode(header.to_string());
    let p = URL_SAFE_NO_PAD.encode(Value::Object(claims.clone()).to_string());
    let input = format!("{h}.{p}");
    let sig = key
        .sign(
            &CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            input.as_bytes(),
        )
        .unwrap();
    format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig))
}

/// A token with no signature at all and `alg` `none`.
pub(crate) fn unsigned(claims: &Map<String, Value>) -> String {
    let h = URL_SAFE_NO_PAD.encode(json!({"alg": "none", "typ": "JWT"}).to_string());
    let p = URL_SAFE_NO_PAD.encode(Value::Object(claims.clone()).to_string());
    format!("{h}.{p}.")
}

/// One Key Vault expiry event, Event Grid schema, as Microsoft's sample
/// writes it (`EXP` as a string of seconds).
pub(crate) fn event(event_type: &str, object_type: &str, name: &str, exp: i64) -> Value {
    let path = match object_type {
        "Secret" => "secrets",
        "Certificate" => "certificates",
        _ => "keys",
    };
    json!({
        "id": "00eccf70-95a7-4e7c-8299-2eb17ee9ad64",
        "topic": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv-test",
        "subject": name,
        "eventType": format!("Microsoft.KeyVault.{event_type}"),
        "eventTime": "2026-11-17T01:08:33.1036736Z",
        "data": {
            "Id": format!("https://kv-test.vault.azure.net/{path}/{name}/{VERSION}"),
            "VaultName": "kv-test",
            "ObjectType": object_type,
            "ObjectName": name,
            "Version": VERSION,
            "NBF": (exp - 365 * 86_400).to_string(),
            "EXP": exp.to_string(),
        },
        "dataVersion": "1",
        "metadataVersion": "1",
    })
}

/// The six expiry events: (event type, object type).
pub(crate) const SIX: [(&str, &str); 6] = [
    ("SecretNearExpiry", "Secret"),
    ("SecretExpired", "Secret"),
    ("CertificateNearExpiry", "Certificate"),
    ("CertificateExpired", "Certificate"),
    ("KeyNearExpiry", "Key"),
    ("KeyExpired", "Key"),
];

/// The handshake Event Grid sends when the subscription is made.
pub(crate) fn validation(code: &str) -> Value {
    json!([{
        "id": "2d1781af-3a4c-4d7c-bd0c-e34b19da4e66",
        "topic": "/subscriptions/00000000-0000-0000-0000-000000000000",
        "subject": "",
        "data": {
            "validationCode": code,
            "validationUrl": "https://rp-eastus2.eventgrid.azure.net:553/eventsubscriptions/x/validate?id=1&t=2&apiVersion=2025-02-15&token=VALIDATIONURLLEAK"
        },
        "eventType": "Microsoft.EventGrid.SubscriptionValidationEvent",
        "eventTime": "2026-11-17T00:00:00Z",
        "metadataVersion": "1",
        "dataVersion": "1"
    }])
}
