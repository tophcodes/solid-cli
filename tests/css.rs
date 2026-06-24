//! End-to-end test against a real Community Solid Server.
//!
//! Spawns CSS via `npx @solid/community-server`, provisions an account + pod +
//! client credentials over the account API, mints a DPoP-bound token with our own
//! crypto, then drives the compiled `solid` binary through put → ls → cat → rm.
//!
//! Skips (passes as a no-op) if `npx` is unavailable or CSS never comes up — so
//! `cargo test` stays green offline. Run the real thing with: `cargo test -- --nocapture`.

use serde_json::{json, Value};
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const PORT: u16 = 3030;
const PORT2: u16 = 3031;
const BIN: &str = env!("CARGO_BIN_EXE_solid");

/// Unique-ish suffix so a reused/leftover server doesn't collide on account/pod names.
fn nonce() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
}

struct Css(Child);
impl Drop for Css {
    fn drop(&mut self) {
        // CSS runs as a `node` grandchild of `npx`; kill the whole process group,
        // not just the npx wrapper, or it orphans and keeps holding the port.
        let pid = self.0.id();
        let _ = Command::new("kill").args(["-KILL", &format!("-{pid}")]).status();
        let _ = self.0.wait();
    }
}

fn npx_available() -> bool {
    Command::new("npx").arg("--version").output().map(|o| o.status.success()).unwrap_or(false)
}

fn start_css(port: u16) -> Option<(Css, String)> {
    let dir = std::env::temp_dir().join(format!("solid-css-test-{port}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).ok()?;
    let child = Command::new("npx")
        .args([
            "--yes", "@solid/community-server",
            "-p", &port.to_string(),
            "-l", "error",
            "-c", "@css:config/default.json",
            "-f", dir.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0) // own group → Drop can kill node grandchild too
        .spawn()
        .ok()?;
    let base = format!("http://localhost:{port}");
    let probe = format!("{base}/.account/");
    for _ in 0..120 {
        if reqwest::blocking::get(&probe).map(|r| r.status().is_success()).unwrap_or(false) {
            return Some((Css(child), base));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    None
}

/// Provision account + pod + client credentials. Returns (pod_base, webid, id, secret).
fn provision(c: &reqwest::blocking::Client, base: &str) -> (String, String, String, String) {
    let n = nonce();
    let created: Value = c
        .post(format!("{base}/.account/account/"))
        .json(&json!({}))
        .send().unwrap().json().unwrap();
    let token = created["authorization"].as_str().expect("authorization token").to_string();
    let auth = format!("CSS-Account-Token {token}");

    let ctrl: Value = c
        .get(format!("{base}/.account/"))
        .header("Authorization", &auth)
        .send().unwrap().json().unwrap();
    let pw_url = ctrl["controls"]["password"]["create"].as_str().unwrap();
    let pod_url = ctrl["controls"]["account"]["pod"].as_str().unwrap();
    let cc_url = ctrl["controls"]["account"]["clientCredentials"].as_str().unwrap();

    let pw_status = c.post(pw_url).header("Authorization", &auth)
        .json(&json!({"email": format!("u{n}@example.com"), "password": "secret123"}))
        .send().unwrap().status();
    assert!(pw_status.is_success(), "add password failed: {pw_status}");

    let pod: Value = c.post(pod_url).header("Authorization", &auth)
        .json(&json!({"name": format!("pod{n}")}))
        .send().unwrap().json().unwrap();
    let pod_base = pod["pod"].as_str().expect("pod url").trim_end_matches('/').to_string();
    let webid = pod["webId"].as_str().expect("webid").to_string();

    let cc: Value = c.post(cc_url).header("Authorization", &auth)
        .json(&json!({"name": "clitest", "webId": webid}))
        .send().unwrap().json().unwrap();
    let id = cc["id"].as_str().expect("cc id").to_string();
    let secret = cc["secret"].as_str().expect("cc secret").to_string();
    (pod_base, webid, id, secret)
}

/// Mint a DPoP-bound access token via grant_type=client_credentials, using our own
/// DPoP proof so the token is bound to a key the CLI also holds.
fn mint_session(
    c: &reqwest::blocking::Client,
    base: &str,
    pod_base: &str,
    id: &str,
    secret: &str,
) -> solid::Session {
    let disc: Value = c
        .get(format!("{base}/.well-known/openid-configuration"))
        .send().unwrap().json().unwrap();
    let token_ep = disc["token_endpoint"].as_str().expect("token_endpoint").to_string();

    let key = solid::DpopKey::generate();
    let key_b64 = key.to_b64();
    let proof = key.proof("POST", &token_ep, None).unwrap();
    let resp = c.post(&token_ep)
        .header("DPoP", proof)
        .basic_auth(id, Some(secret))
        .form(&[("grant_type", "client_credentials"), ("scope", "webid")])
        .send().unwrap();
    let status = resp.status();
    let body = resp.text().unwrap();
    assert!(status.is_success(), "token mint failed ({status}): {body}");
    let tok: Value = serde_json::from_str(&body).unwrap();

    solid::Session {
        issuer: base.to_string(),
        base: pod_base.to_string(),
        token_endpoint: token_ep,
        client_id: id.to_string(),
        client_secret: Some(secret.to_string()),
        refresh_token: None,
        access_token: tok["access_token"].as_str().unwrap().to_string(),
        expires_at: solid::now() + tok["expires_in"].as_u64().unwrap_or(3600),
        key: key_b64,
    }
}

/// Run the `solid` binary with the given session file and optional stdin.
fn solid_cmd(session: &str, args: &[&str], stdin: Option<&[u8]>) -> std::process::Output {
    let mut child = Command::new(BIN)
        .env("SOLID_SESSION", session)
        .args(args)
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(data) = stdin {
        child.stdin.take().unwrap().write_all(data).unwrap();
    }
    child.wait_with_output().unwrap()
}

#[test]
fn crud_roundtrip_against_css() {
    if !npx_available() {
        eprintln!("SKIP: npx not available — cannot start Community Solid Server");
        return;
    }
    let Some((_css, base)) = start_css(PORT) else {
        eprintln!("SKIP: Community Solid Server did not come up");
        return;
    };

    let http = reqwest::blocking::Client::new();
    let (pod_base, _webid, id, secret) = provision(&http, &base);
    let session = mint_session(&http, &base, &pod_base, &id, &secret);

    let session_file = std::env::temp_dir().join(format!("solid-test-session-{PORT}.json"));
    std::fs::write(&session_file, serde_json::to_string(&session).unwrap()).unwrap();
    let sf = session_file.to_str().unwrap();

    // PUT a resource
    let out = solid_cmd(sf, &["put", "hello.txt"], Some(b"hello world"));
    assert!(out.status.success(), "put failed: {}", String::from_utf8_lossy(&out.stderr));

    // LS the pod root — should list the new resource
    let out = solid_cmd(sf, &["ls", "/"], None);
    let listing = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "ls failed: {}", String::from_utf8_lossy(&out.stderr));
    assert!(listing.contains("hello.txt"), "ls missing hello.txt; got:\n{listing}");

    // CAT it back — bytes must round-trip
    let out = solid_cmd(sf, &["cat", "hello.txt"], None);
    assert!(out.status.success(), "cat failed: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.stdout, b"hello world");

    // RM it
    let out = solid_cmd(sf, &["rm", "hello.txt"], None);
    assert!(out.status.success(), "rm failed: {}", String::from_utf8_lossy(&out.stderr));

    // LS again — gone
    let out = solid_cmd(sf, &["ls", "/"], None);
    let listing = String::from_utf8_lossy(&out.stdout);
    assert!(!listing.contains("hello.txt"), "hello.txt still present after rm:\n{listing}");

    // CAT a deleted resource fails
    let out = solid_cmd(sf, &["cat", "hello.txt"], None);
    assert!(!out.status.success(), "cat of deleted resource should fail");

    let _ = std::fs::remove_file(&session_file);
}

/// Provision a fresh pod and return a ready-to-use session for it.
fn fresh_session(http: &reqwest::blocking::Client, base: &str) -> solid::Session {
    let (pod_base, _webid, id, secret) = provision(http, base);
    mint_session(http, base, &pod_base, &id, &secret)
}

/// Run the binary with a profiles directory (`$SOLID_CONFIG_DIR`) and optional stdin.
fn solid_cfg(cfg_dir: &str, args: &[&str], stdin: Option<&[u8]>) -> std::process::Output {
    let mut child = Command::new(BIN)
        .env("SOLID_CONFIG_DIR", cfg_dir)
        .env_remove("SOLID_SESSION")
        .args(args)
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(data) = stdin {
        child.stdin.take().unwrap().write_all(data).unwrap();
    }
    child.wait_with_output().unwrap()
}

#[test]
fn multi_profile_addressing() {
    if !npx_available() {
        eprintln!("SKIP: npx not available — cannot start Community Solid Server");
        return;
    }
    let Some((_css, base)) = start_css(PORT2) else {
        eprintln!("SKIP: Community Solid Server did not come up");
        return;
    };

    // Two independent pods on the same server -> two profiles.
    let http = reqwest::blocking::Client::new();
    let work = fresh_session(&http, &base);
    let perso = fresh_session(&http, &base);

    let cfg = std::env::temp_dir().join(format!("solid-cfg-{PORT2}"));
    let _ = std::fs::remove_dir_all(&cfg);
    let profiles = cfg.join("profiles");
    std::fs::create_dir_all(&profiles).unwrap();
    std::fs::write(profiles.join("work.json"), serde_json::to_string(&work).unwrap()).unwrap();
    std::fs::write(profiles.join("perso.json"), serde_json::to_string(&perso).unwrap()).unwrap();
    std::fs::write(cfg.join("config.json"), r#"{"default":"work"}"#).unwrap();
    let c = cfg.to_str().unwrap();

    // bare path -> default profile (work)
    let out = solid_cfg(c, &["put", "a.txt"], Some(b"alpha"));
    assert!(out.status.success(), "put work failed: {}", String::from_utf8_lossy(&out.stderr));
    // inline alias -> perso
    let out = solid_cfg(c, &["put", "perso:b.txt"], Some(b"beta"));
    assert!(out.status.success(), "put perso failed: {}", String::from_utf8_lossy(&out.stderr));

    // each pod sees only its own resource — profiles are isolated
    let work_ls = String::from_utf8_lossy(&solid_cfg(c, &["ls", "/"], None).stdout).into_owned();
    assert!(work_ls.contains("a.txt"), "work missing a.txt:\n{work_ls}");
    assert!(!work_ls.contains("b.txt"), "work leaked b.txt:\n{work_ls}");

    let perso_ls = String::from_utf8_lossy(&solid_cfg(c, &["ls", "perso:/"], None).stdout).into_owned();
    assert!(perso_ls.contains("b.txt"), "perso missing b.txt:\n{perso_ls}");
    assert!(!perso_ls.contains("a.txt"), "perso leaked a.txt:\n{perso_ls}");

    // inline alias and --profile flag both reach perso
    assert_eq!(solid_cfg(c, &["cat", "perso:b.txt"], None).stdout, b"beta");
    assert_eq!(solid_cfg(c, &["--profile", "perso", "cat", "b.txt"], None).stdout, b"beta");

    // `profiles` lists both, default marked
    let listing = String::from_utf8_lossy(&solid_cfg(c, &["profiles"], None).stdout).into_owned();
    assert!(listing.contains("work") && listing.contains("perso"), "profiles:\n{listing}");
    assert!(listing.contains("* work"), "default not marked:\n{listing}");

    let _ = std::fs::remove_dir_all(&cfg);
}
