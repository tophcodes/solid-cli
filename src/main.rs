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
    /// Profile to use for this command (overrides the default; `alias:path` wins over this)
    #[arg(short = 'p', long, global = true)]
    profile: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Interactive OIDC login, stored as a named profile
    Login {
        /// Profile name to log in as
        #[arg(long = "as", value_name = "NAME", default_value = "default")]
        name: String,
    },
    /// List profiles (the default is marked with *)
    Profiles,
    /// Set the default profile
    Use { name: String },
    /// Remove a profile
    Logout { name: Option<String> },
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
    let p = cli.profile.as_deref();
    match cli.cmd {
        Cmd::Login { name } => login(&name).await,
        Cmd::Profiles => profiles(),
        Cmd::Use { name } => use_profile(&name),
        Cmd::Logout { name } => logout(name),
        Cmd::Ls { path } => ls(&path, p).await,
        Cmd::Cat { path } => cat(&path, p).await,
        Cmd::Put { path, content_type } => put(&path, content_type, p).await,
        Cmd::Rm { path } => rm(&path, p).await,
    }
}

// ---------- addressing ----------

/// Resolve a path argument to (profile name, its session, target URL).
/// Profile selection: inline `alias:` > `--profile` flag > configured default.
fn resolve_target(raw: &str, flag: Option<&str>) -> Result<(String, Session, String)> {
    let (inline, locator) = parse_locator(raw, &list_profiles());
    let name = inline
        .or_else(|| flag.map(String::from))
        .or_else(default_profile)
        .ok_or_else(|| anyhow!("no profile — run `solid login` or use `profile:path`"))?;
    let session = load_profile(&name)?;
    let url = resolve(&session.base, locator);
    Ok((name, session, url))
}

// ---------- auth ----------

/// Ensure a fresh access token, refreshing via the DPoP-bound refresh_token if expired.
async fn fresh_token(name: &str, s: &mut Session) -> Result<()> {
    if now() < s.expires_at {
        return Ok(());
    }
    let rt = s.refresh_token.clone().ok_or_else(|| anyhow!("token expired, no refresh — re-login"))?;
    let key = DpopKey::try_from(s.key.as_str())?;
    let proof = key.proof("POST", &s.token_endpoint, None)?;
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
    save_profile(name, s)?;
    Ok(())
}

/// Sign an LDP request with a DPoP proof bound to the session's access token and send it.
async fn send_signed(
    method: reqwest::Method,
    url: &str,
    accept: Option<&str>,
    s: &Session,
) -> Result<reqwest::Response> {
    let key = DpopKey::try_from(s.key.as_str())?;
    let proof = key.proof(method.as_str(), url, Some(&s.access_token))?;
    let mut req = reqwest::Client::new()
        .request(method, url)
        .header("Authorization", format!("DPoP {}", s.access_token))
        .header("DPoP", proof);
    if let Some(a) = accept {
        req = req.header("Accept", a);
    }
    Ok(req.send().await?)
}

// ---------- profile management ----------

async fn login(name: &str) -> Result<()> {
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
    let key = DpopKey::generate();
    let key_b64 = key.to_b64();

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
    let proof = key.proof("POST", &token_ep, None)?;
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

    let first = list_profiles().is_empty();
    save_profile(name, &s)?;
    if first {
        set_default(name)?;
    }
    println!("Logged in as '{name}'. Profile at {}", profile_path(name)?.display());
    Ok(())
}

fn profiles() -> Result<()> {
    let names = list_profiles();
    if names.is_empty() {
        println!("no profiles — run `solid login`");
        return Ok(());
    }
    let def = default_profile();
    for name in names {
        let marker = if def.as_deref() == Some(&name) { "*" } else { " " };
        let base = load_profile(&name).map(|s| s.base).unwrap_or_default();
        println!("{marker} {name}\t{base}");
    }
    Ok(())
}

fn use_profile(name: &str) -> Result<()> {
    if !list_profiles().iter().any(|p| p == name) {
        bail!("no such profile: {name}");
    }
    set_default(name)?;
    println!("default profile: {name}");
    Ok(())
}

fn logout(name: Option<String>) -> Result<()> {
    let name = name.or_else(default_profile).ok_or_else(|| anyhow!("no profile to remove"))?;
    remove_profile(&name)?;
    println!("removed profile: {name}");
    Ok(())
}

fn catch_code(state: &str) -> Result<String> {
    let server = tiny_http::Server::http("127.0.0.1:9876")
        .map_err(|e| anyhow!("callback server: {e}"))?;
    for req in server.incoming_requests() {
        let url = req.url().to_string();
        let query = url.split_once('?').map(|(_, q)| q).unwrap_or("");
        let mut code = None;
        let mut got_state = None;
        for kv in query.split('&') {
            if let Some((k, v)) = kv.split_once('=') {
                match k {
                    "code" => code = Some(urldec(v)),
                    "state" => got_state = Some(urldec(v)),
                    _ => {}
                }
            }
        }
        let _ = req.respond(tiny_http::Response::from_string(
            "<h2>Solid CLI: logged in. You can close this tab.</h2>",
        ).with_header("Content-Type: text/html".parse::<tiny_http::Header>().unwrap()));
        // ignore stray hits (favicon, etc.) that carry no auth params
        if code.is_none() && got_state.is_none() {
            continue;
        }
        if got_state.as_deref() != Some(state) {
            bail!("state mismatch");
        }
        return code.ok_or_else(|| anyhow!("no code in callback"));
    }
    bail!("callback server closed")
}

// ---------- commands ----------

async fn ls(path: &str, flag: Option<&str>) -> Result<()> {
    let (name, mut s, mut url) = resolve_target(path, flag)?;
    if !url.ends_with('/') {
        url.push('/');
    }
    fresh_token(&name, &mut s).await?;
    let resp = send_signed(reqwest::Method::GET, &url, Some("text/turtle"), &s).await?;
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        bail!("{status}: {body}");
    }
    for child in parse_contains(&body) {
        let short = child.trim_start_matches(url.as_str());
        println!("{}", if short.is_empty() { &child } else { short });
    }
    Ok(())
}

async fn cat(path: &str, flag: Option<&str>) -> Result<()> {
    let (name, mut s, url) = resolve_target(path, flag)?;
    fresh_token(&name, &mut s).await?;
    let resp = send_signed(reqwest::Method::GET, &url, None, &s).await?;
    let status = resp.status();
    let bytes = resp.bytes().await?;
    if !status.is_success() {
        bail!("{status}: {}", String::from_utf8_lossy(&bytes));
    }
    std::io::stdout().write_all(&bytes)?;
    Ok(())
}

async fn put(path: &str, content_type: Option<String>, flag: Option<&str>) -> Result<()> {
    let (name, mut s, url) = resolve_target(path, flag)?;
    let ct = content_type.unwrap_or_else(|| guess_type(&url));
    let mut body = Vec::new();
    std::io::stdin().read_to_end(&mut body)?;

    fresh_token(&name, &mut s).await?;
    let key = DpopKey::try_from(s.key.as_str())?;
    let proof = key.proof("PUT", &url, Some(&s.access_token))?;
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

async fn rm(path: &str, flag: Option<&str>) -> Result<()> {
    let (name, mut s, url) = resolve_target(path, flag)?;
    fresh_token(&name, &mut s).await?;
    let resp = send_signed(reqwest::Method::DELETE, &url, None, &s).await?;
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
