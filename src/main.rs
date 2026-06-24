// solid — tiny LDP CRUD CLI over Solid pods. Solid-OIDC login w/ DPoP-bound tokens.
use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use solid::*;
use std::io::{Read, Write};

const REDIRECT: &str = "http://localhost:9876/callback";
const SCOPE: &str = "openid webid offline_access";

#[derive(Parser)]
#[command(name = "solid", about = "Tiny LDP CRUD over Solid pods")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Interactive OIDC login
    Login,
    /// List container contents
    Ls { path: String },
    /// Print a resource to stdout
    Cat { path: String },
    /// Write/overwrite a resource from stdin
    Put {
        path: String,
        /// Content-Type (else guessed from extension)
        #[arg(short = 't', long)]
        content_type: Option<String>,
    },
    /// Delete a resource
    Rm { path: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Login => login().await,
        Cmd::Ls { path } => ls(&path).await,
        Cmd::Cat { path } => cat(&path).await,
        Cmd::Put { path, content_type } => put(&path, content_type).await,
        Cmd::Rm { path } => rm(&path).await,
    }
}

// ---------- auth ----------

/// Ensure a fresh access token, refreshing via the DPoP-bound refresh_token if expired.
async fn fresh_token(s: &mut Session) -> Result<()> {
    if now() < s.expires_at {
        return Ok(());
    }
    let rt = s.refresh_token.clone().ok_or_else(|| anyhow!("token expired, no refresh — re-login"))?;
    let key = key_from_b64(&s.key)?;
    let proof = dpop_proof(&key, "POST", &s.token_endpoint, None)?;
    let client = reqwest::Client::new();
    let mut req = client.post(&s.token_endpoint).header("DPoP", proof).form(&[
        ("grant_type", "refresh_token"),
        ("refresh_token", rt.as_str()),
        ("scope", SCOPE),
        ("client_id", s.client_id.as_str()),
    ]);
    if let Some(sec) = &s.client_secret {
        req = req.basic_auth(&s.client_id, Some(sec));
    }
    let resp = req.send().await?;
    if !resp.status().is_success() {
        bail!("refresh failed: {}", resp.text().await.unwrap_or_default());
    }
    apply_token(s, resp.json().await?);
    save(s)?;
    Ok(())
}

/// Authenticated request with an optional Accept header.
async fn authed_with(
    method: reqwest::Method,
    url: &str,
    accept: Option<&str>,
) -> Result<reqwest::Response> {
    let mut s = load()?;
    fresh_token(&mut s).await?;
    let key = key_from_b64(&s.key)?;
    let proof = dpop_proof(&key, method.as_str(), url, Some(&s.access_token))?;
    let mut req = reqwest::Client::new()
        .request(method, url)
        .header("Authorization", format!("DPoP {}", s.access_token))
        .header("DPoP", proof);
    if let Some(a) = accept {
        req = req.header("Accept", a);
    }
    Ok(req.send().await?)
}

// ---------- login ----------

async fn login() -> Result<()> {
    let issuer = prompt("Issuer (OIDC provider)", "https://solidcommunity.net")?;
    let issuer = issuer.trim_end_matches('/').to_string();
    let base = prompt("Pod base URL", &issuer)?;

    let client = reqwest::Client::new();
    // 1. discovery
    let cfg: serde_json::Value = client
        .get(format!("{}/.well-known/openid-configuration", issuer))
        .send().await?.json().await
        .context("OIDC discovery failed")?;
    let auth_ep = cfg["authorization_endpoint"].as_str().ok_or_else(|| anyhow!("no authorization_endpoint"))?.to_string();
    let token_ep = cfg["token_endpoint"].as_str().ok_or_else(|| anyhow!("no token_endpoint"))?.to_string();
    let reg_ep = cfg["registration_endpoint"].as_str().ok_or_else(|| anyhow!("no registration_endpoint"))?.to_string();

    // 2. dynamic client registration
    let reg: serde_json::Value = client.post(&reg_ep).json(&serde_json::json!({
        "client_name": "solid-cli",
        "redirect_uris": [REDIRECT],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "scope": SCOPE,
        "token_endpoint_auth_method": "client_secret_basic",
    })).send().await?.json().await.context("client registration failed")?;
    let client_id = reg["client_id"].as_str().ok_or_else(|| anyhow!("no client_id"))?.to_string();
    let client_secret = reg["client_secret"].as_str().map(|s| s.to_string());

    // 3. PKCE + ephemeral DPoP key
    let verifier = rand_b64(32);
    let challenge = s256(&verifier);
    let state = rand_b64(16);
    let (key, key_b64) = gen_key();

    let auth_url = format!(
        "{auth_ep}?response_type=code&client_id={cid}&redirect_uri={redir}&scope={scope}&state={state}&code_challenge={ch}&code_challenge_method=S256&prompt=consent",
        cid = urlenc(&client_id), redir = urlenc(REDIRECT), scope = urlenc(SCOPE),
        state = urlenc(&state), ch = challenge,
    );

    println!("Opening browser…\n  {auth_url}");
    let _ = open::that(&auth_url);

    // 4. catch the redirect
    let code = tokio::task::spawn_blocking(move || catch_code(&state)).await??;

    // 5. token exchange (DPoP-bound)
    let proof = dpop_proof(&key, "POST", &token_ep, None)?;
    let mut req = client.post(&token_ep).header("DPoP", proof).form(&[
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", REDIRECT),
        ("code_verifier", verifier.as_str()),
        ("client_id", client_id.as_str()),
    ]);
    if let Some(sec) = &client_secret {
        req = req.basic_auth(&client_id, Some(sec));
    }
    let resp = req.send().await?;
    if !resp.status().is_success() {
        bail!("token exchange failed: {}", resp.text().await.unwrap_or_default());
    }

    let mut s = Session {
        issuer, base: base.trim_end_matches('/').to_string(),
        token_endpoint: token_ep, client_id, client_secret,
        refresh_token: None, access_token: String::new(), expires_at: 0, key: key_b64,
    };
    apply_token(&mut s, resp.json().await?);
    save(&s)?;
    println!("Logged in. Session at {}", config_path()?.display());
    Ok(())
}

fn catch_code(state: &str) -> Result<String> {
    let server = tiny_http::Server::http("127.0.0.1:9876")
        .map_err(|e| anyhow!("callback server: {e}"))?;
    for req in server.incoming_requests() {
        let url = req.url().to_string();
        let q = url.splitn(2, '?').nth(1).unwrap_or("");
        let mut code = None;
        let mut got_state = None;
        for kv in q.split('&') {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            match k {
                "code" => code = Some(urldec(v)),
                "state" => got_state = Some(urldec(v)),
                _ => {}
            }
        }
        let _ = req.respond(tiny_http::Response::from_string(
            "<h2>Solid CLI: logged in. You can close this tab.</h2>",
        ).with_header("Content-Type: text/html".parse::<tiny_http::Header>().unwrap()));
        if got_state.as_deref() != Some(state) {
            bail!("state mismatch");
        }
        return code.ok_or_else(|| anyhow!("no code in callback"));
    }
    bail!("callback server closed")
}

// ---------- commands ----------

async fn ls(path: &str) -> Result<()> {
    let s = load()?;
    let mut url = resolve(&s.base, path);
    if !url.ends_with('/') {
        url.push('/');
    }
    let resp = authed_with(reqwest::Method::GET, &url, Some("text/turtle")).await?;
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        bail!("{status}: {body}");
    }
    for child in parse_contains(&body) {
        let name = child.trim_start_matches(url.as_str());
        println!("{}", if name.is_empty() { &child } else { name });
    }
    Ok(())
}

async fn cat(path: &str) -> Result<()> {
    let url = resolve(&load()?.base, path);
    let resp = authed_with(reqwest::Method::GET, &url, None).await?;
    let status = resp.status();
    let bytes = resp.bytes().await?;
    if !status.is_success() {
        bail!("{status}: {}", String::from_utf8_lossy(&bytes));
    }
    std::io::stdout().write_all(&bytes)?;
    Ok(())
}

async fn put(path: &str, content_type: Option<String>) -> Result<()> {
    let mut s = load()?;
    let url = resolve(&s.base, path);
    let ct = content_type.unwrap_or_else(|| guess_type(&url));
    let mut body = Vec::new();
    std::io::stdin().read_to_end(&mut body)?;

    fresh_token(&mut s).await?;
    let key = key_from_b64(&s.key)?;
    let proof = dpop_proof(&key, "PUT", &url, Some(&s.access_token))?;
    let resp = reqwest::Client::new()
        .put(&url)
        .header("Authorization", format!("DPoP {}", s.access_token))
        .header("DPoP", proof)
        .header("Content-Type", ct)
        .body(body)
        .send().await?;
    if !resp.status().is_success() {
        bail!("{}: {}", resp.status(), resp.text().await.unwrap_or_default());
    }
    println!("PUT {url}");
    Ok(())
}

async fn rm(path: &str) -> Result<()> {
    let url = resolve(&load()?.base, path);
    let resp = authed_with(reqwest::Method::DELETE, &url, None).await?;
    if !resp.status().is_success() {
        bail!("{}: {}", resp.status(), resp.text().await.unwrap_or_default());
    }
    println!("DELETE {url}");
    Ok(())
}

fn prompt(label: &str, default: &str) -> Result<String> {
    print!("{label} [{default}]: ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let line = line.trim();
    Ok(if line.is_empty() { default.to_string() } else { line.to_string() })
}
