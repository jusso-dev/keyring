//! Certificate list, detail and downloads.

mod support;

use axum::http::StatusCode;
use support::body_text;

const DAY: i64 = 86_400;

fn now() -> i64 {
    keyring::azure::secrets::now_ts()
}

#[tokio::test]
async fn list_shows_expiry_bands_and_thumbprints() {
    let w = support::world().await;
    let n = now();
    let der = support::pem_first_cert(support::TEST_CERT_PEM);
    let p = support::certs::default_policy(false, false);
    w.kv.state
        .add_cert_version("expired", der.clone(), p.clone(), |v| v.exp = Some(n - DAY));
    w.kv.state
        .add_cert_version("soon", der.clone(), p.clone(), |v| {
            v.exp = Some(n + 10 * DAY)
        });
    w.kv.state
        .add_cert_version("quarter", der.clone(), p.clone(), |v| {
            v.exp = Some(n + 60 * DAY)
        });
    w.kv.state
        .add_cert_version("fine", der.clone(), p.clone(), |v| {
            v.exp = Some(n + 300 * DAY)
        });
    w.kv.state.add_cert_version("off", der.clone(), p, |v| {
        v.enabled = false;
        v.tags.insert("env".into(), "prod".into());
    });
    let (status, html) = w.page("/v/kv-test/certificates").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("5 certificates"));
    assert!(
        html.contains("1 expired")
            && html.contains("1 expiring within 30 days")
            && html.contains("1 more within 90 days")
    );
    assert!(html.contains("badge-error\">Expired"));
    assert!(html.contains("Expires within 30 days"));
    assert!(html.contains("Expires within 90 days"));
    assert!(html.contains(">Disabled<"));
    assert!(html.contains("env=prod"));
    let thumb =
        keyring::azure::certs::thumbprint_hex(Some(&support::certs::thumb(der.as_ref().unwrap())));
    assert!(html.contains(&thumb));
    let (_, html) = w.page("/v/kv-test/certificates?show=30").await;
    assert!(html.contains(">soon<") && html.contains(">expired<") && !html.contains(">quarter<"));
    let bearers = w.kv.state.bearers.lock().unwrap().clone();
    assert!(
        bearers
            .iter()
            .all(|b| b.starts_with("Bearer obo:https://vault.azure.net/.default"))
    );
}

#[tokio::test]
async fn empty_and_forbidden() {
    let w = support::world().await;
    let (_, html) = w.page("/v/kv-test/certificates").await;
    assert!(html.contains("This vault has no certificates yet"));
    *w.kv.state.fail.lock().unwrap() = Some((403, "Forbidden"));
    let (status, html) = w.page("/v/kv-test/certificates").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(html.contains("Key Vault Reader role on this vault"));
}

#[tokio::test]
async fn detail_shows_subject_policy_and_versions() {
    let w = support::world().await;
    let v1 = w.kv.state.add_cert("web-tls", false, "pfx");
    let v2 = w.kv.state.add_cert("web-tls", false, "pfx");
    let (status, html) = w.page("/v/kv-test/certificates/web-tls").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("CN=keyring.test"));
    assert!(html.contains("www.keyring.test"));
    assert!(html.contains("self-signed"));
    assert!(html.contains("1 Jan 2036"));
    assert!(html.contains("Renews automatically at 80% of its lifetime"));
    assert!(html.contains("No, it stays in Key Vault"));
    assert!(html.contains(&v1[..8]) && html.contains(&v2[..8]));
    assert!(
        !html.contains("Download with private key"),
        "not exportable"
    );
    // Nothing read the backing secret.
    assert!(w.kv.state.value_reads().is_empty());
}

#[tokio::test]
async fn cer_downloads_der_and_pem() {
    let w = support::world().await;
    w.kv.state.add_cert("web-tls", false, "pfx");
    let res = w.get("/v/kv-test/certificates/web-tls/cer").await;
    assert_eq!(res.status(), StatusCode::OK);
    let h = res.headers().clone();
    assert_eq!(h.get("content-type").unwrap(), "application/pkix-cert");
    assert_eq!(
        h.get("content-disposition").unwrap(),
        "attachment; filename=\"web-tls.cer\""
    );
    assert!(
        h.get("cache-control")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("no-store")
    );
    let bytes = http_body_util::BodyExt::collect(res.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(
        Some(bytes.to_vec()),
        support::pem_first_cert(support::TEST_CERT_PEM)
    );

    let res = w
        .get("/v/kv-test/certificates/web-tls/cer?format=pem")
        .await;
    let pem = body_text(res).await;
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(!pem.contains("PRIVATE KEY"));
    assert!(w.kv.state.value_reads().is_empty());
}

#[tokio::test]
async fn pfx_only_when_exportable() {
    let w = support::world().await;
    w.kv.state.add_cert("locked", false, "c2VjcmV0");
    let (status, html) = w.page("/v/kv-test/certificates/locked/download-key").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(html.contains("can&#39;t be downloaded"));
    let res = w
        .post(
            "/v/kv-test/certificates/locked/download-key",
            &[("confirm_name", "locked")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(w.kv.state.value_reads().is_empty());
}

#[tokio::test]
async fn pfx_needs_warning_and_typed_name() {
    let w = support::world().await;
    // base64 of "PFXBYTES"
    w.kv.state.add_cert("web-tls", true, "UEZYQllURVM=");
    let (_, html) = w.page("/v/kv-test/certificates/web-tls").await;
    assert!(html.contains("Download with private key"));
    let (status, html) = w.page("/v/kv-test/certificates/web-tls/download-key").await;
    assert_eq!(status, StatusCode::OK);
    assert!(html.contains("private key"));
    assert!(html.contains("notice-error"), "second warning");
    assert!(
        w.kv.state.value_reads().is_empty(),
        "the warning page reads nothing"
    );

    let res = w
        .post(
            "/v/kv-test/certificates/web-tls/download-key",
            &[("confirm_name", "web")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(body_text(res).await.contains("Nothing was downloaded"));
    assert!(w.kv.state.value_reads().is_empty());

    let res = w
        .post(
            "/v/kv-test/certificates/web-tls/download-key",
            &[("confirm_name", "web-tls")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::OK);
    let h = res.headers().clone();
    assert_eq!(h.get("content-type").unwrap(), "application/x-pkcs12");
    assert!(
        h.get("cache-control")
            .unwrap()
            .to_str()
            .unwrap()
            .contains("no-store")
    );
    assert_eq!(
        h.get("content-disposition").unwrap(),
        "attachment; filename=\"web-tls.pfx\""
    );
    let bytes = http_body_util::BodyExt::collect(res.into_body())
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&bytes[..], b"PFXBYTES");
}

#[tokio::test]
async fn pfx_forged_token_refused() {
    let mut w = support::world().await;
    w.kv.state.add_cert("web-tls", true, "UEZYQllURVM=");
    w.csrf = "forged".into();
    let res = w
        .post(
            "/v/kv-test/certificates/web-tls/download-key",
            &[("confirm_name", "web-tls")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(w.kv.state.value_reads().is_empty());
}

#[tokio::test]
async fn bad_names_and_versions() {
    let w = support::world().await;
    let (status, _) = w.page("/v/kv-test/certificates/bad_name").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    w.kv.state.add_cert("web-tls", false, "x");
    let (status, _) = w
        .page("/v/kv-test/certificates/web-tls/cer?version=..%2F..")
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = w.page("/v/kv-test/certificates/nope").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn backing_secret_cannot_bypass_private_key_download() {
    let w = support::world().await;
    w.kv.state.add_cert("web-tls", true, "UEZYQllURVM=");
    // Mark the backing secret as managed, as Key Vault does.
    w.kv.state
        .secrets
        .lock()
        .unwrap()
        .get_mut("web-tls")
        .unwrap()
        .managed = true;
    let (_, html) = w.page("/v/kv-test/secrets/web-tls").await;
    assert!(html.contains("belongs to the certificate"));
    assert!(
        !html.contains("action=\"/v/kv-test/secrets/web-tls/reveal\""),
        "no Show value button"
    );
    assert!(!html.contains("/v/kv-test/secrets/web-tls/delete"));
    for (path, fields) in [
        ("/v/kv-test/secrets/web-tls/reveal", vec![]),
        (
            "/v/kv-test/secrets/web-tls/value",
            vec![("value", "x"), ("enabled", "on")],
        ),
        ("/v/kv-test/secrets/web-tls/edit", vec![("enabled", "on")]),
        ("/v/kv-test/secrets/web-tls/enabled", vec![("state", "off")]),
        (
            "/v/kv-test/secrets/web-tls/delete",
            vec![("confirm_name", "web-tls")],
        ),
    ] {
        let res = w.post(path, &fields).await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN, "{path}");
        let html = body_text(res).await;
        assert!(html.contains("belongs to a certificate"), "{path}");
        // The button names where it goes, not "Try again".
        assert!(
            html.contains("href=\"/v/kv-test/certificates/web-tls\">Open the certificate</a>"),
            "{path}"
        );
    }
    let (_, html) = w.page("/v/kv-test/secrets/web-tls/versions").await;
    assert!(!html.contains("action=\"/v/kv-test/secrets/web-tls/reveal\""));
    assert!(
        w.kv.state.value_reads().is_empty(),
        "no value read through the secrets pages"
    );
}

#[tokio::test]
async fn detail_says_when_a_section_couldnt_load() {
    let w = support::world().await;
    w.kv.state.add_cert("web-tls", false, "x");
    *w.kv.state.fail_path.lock().unwrap() = Some("/versions".into());
    *w.kv.state.fail.lock().unwrap() = Some((500, "InternalError"));
    let (status, html) = w.page("/v/kv-test/certificates/web-tls").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        html.contains("Couldn&#39;t load this certificate&#39;s versions just now"),
        "{html}"
    );
    assert!(!html.contains("No versions listed"));
    *w.kv.state.fail_path.lock().unwrap() = Some("/pending".into());
    let (_, html) = w.page("/v/kv-test/certificates/web-tls").await;
    assert!(html.contains("Couldn&#39;t load whether a request is pending just now"));
}

#[tokio::test]
async fn status_cell_is_never_empty() {
    let w = support::world().await;
    w.kv.state.add_cert_version(
        "no-expiry",
        support::pem_first_cert(support::TEST_CERT_PEM),
        support::certs::default_policy(false, false),
        |v| v.exp = None,
    );
    let (_, html) = w.page("/v/kv-test/certificates").await;
    let row = html.split(">no-expiry<").nth(1).unwrap();
    let cell = row
        .split("<td>")
        .nth(1)
        .unwrap()
        .split("</td>")
        .next()
        .unwrap();
    assert!(cell.contains("Active"), "{cell}");
}

#[tokio::test]
async fn private_key_download_checks_the_token_before_key_vault() {
    let mut w = support::world().await;
    w.csrf = "forged".into();
    // A name that doesn't exist: still a 403, and Key Vault isn't asked.
    let res = w
        .post(
            "/v/kv-test/certificates/no-such-cert/download-key",
            &[("confirm_name", "no-such-cert")],
        )
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(w.kv.state.log.lock().unwrap().is_empty());
}
