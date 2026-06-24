// Reusable core: crypto/DPoP, session, tiny parsers. Shared by the binary and tests.
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Clone)]
pub struct Session {
    pub issuer: String,
    pub base: String,
    pub token_endpoint: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub refresh_token: Option<String>,
    pub access_token: String,
    pub expires_at: u64,
    pub key: String, // base64url of P-256 secret scalar (32 bytes)
}

#[derive(Deserialize)]
pub struct TokenResp {
    pub access_token: String,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

pub fn rand_b64(n: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    B64.encode(buf)
}

pub fn s256(s: &str) -> String {
    B64.encode(Sha256::digest(s.as_bytes()))
}

/// A P-256 keypair used to sign DPoP proofs. The secret scalar is persisted as
/// base64url in the session; parse it back with `DpopKey::try_from(&str)`.
pub struct DpopKey(SigningKey);

impl DpopKey {
    /// Generate a fresh keypair.
    pub fn generate() -> Self {
        Self(SigningKey::random(&mut rand::rngs::OsRng))
    }

    /// base64url-encoded secret scalar, for storing in the session.
    pub fn to_b64(&self) -> String {
        B64.encode(self.0.to_bytes())
    }

    /// Build a DPoP proof JWT for (method, url), optionally bound to an access token (ath).
    pub fn proof(&self, method: &str, url: &str, token: Option<&str>) -> Result<String> {
        let pt = self.0.verifying_key().to_encoded_point(false);
        let jwk = serde_json::json!({
            "kty": "EC", "crv": "P-256",
            "x": B64.encode(pt.x().unwrap()),
            "y": B64.encode(pt.y().unwrap()),
        });
        let header = serde_json::json!({ "typ": "dpop+jwt", "alg": "ES256", "jwk": jwk });
        let mut payload = serde_json::json!({
            "htu": url, "htm": method, "jti": rand_b64(16), "iat": now(),
        });
        if let Some(t) = token {
            payload["ath"] = serde_json::Value::String(s256(t));
        }
        let signing_input = format!(
            "{}.{}",
            B64.encode(serde_json::to_vec(&header)?),
            B64.encode(serde_json::to_vec(&payload)?),
        );
        let sig: Signature = self.0.sign(signing_input.as_bytes());
        Ok(format!("{}.{}", signing_input, B64.encode(sig.to_bytes())))
    }
}

/// Parse a key from the base64url secret scalar stored in the session. Fallible
/// (the input may be malformed), hence `TryFrom` rather than `From`.
impl TryFrom<&str> for DpopKey {
    type Error = anyhow::Error;
    fn try_from(b64: &str) -> Result<Self> {
        let bytes = B64.decode(b64)?;
        Ok(Self(SigningKey::from_bytes(bytes.as_slice().into())?))
    }
}

pub fn apply_token(s: &mut Session, t: TokenResp) {
    s.access_token = t.access_token;
    s.expires_at = now() + t.expires_in.unwrap_or(3600).saturating_sub(30);
    if t.refresh_token.is_some() {
        s.refresh_token = t.refresh_token;
    }
}

// ---------- profiles ----------
//
// Each profile is one Session, stored at `<config>/profiles/<name>.json`. The
// chosen default lives in `<config>/config.json`. Env overrides:
//   $SOLID_SESSION    — single-file mode: one profile named "default" at that path
//                       (used by the e2e test; keeps the simple case trivial).
//   $SOLID_CONFIG_DIR — base directory instead of ~/.config/solid.
use std::path::PathBuf;

fn single_file() -> Option<PathBuf> {
    std::env::var("SOLID_SESSION").ok().map(PathBuf::from)
}

fn base_dir() -> Result<PathBuf> {
    let dir = match std::env::var("SOLID_CONFIG_DIR") {
        Ok(d) => PathBuf::from(d),
        Err(_) => dirs::config_dir().ok_or_else(|| anyhow!("no config dir"))?.join("solid"),
    };
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

pub fn profile_path(name: &str) -> Result<PathBuf> {
    if let Some(p) = single_file() {
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent)?;
        }
        return Ok(p);
    }
    let dir = base_dir()?.join("profiles");
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join(format!("{name}.json")))
}

pub fn load_profile(name: &str) -> Result<Session> {
    let raw = std::fs::read_to_string(profile_path(name)?)
        .map_err(|_| anyhow!("no profile '{name}' — run `solid login --as {name}`"))?;
    Ok(serde_json::from_str(&raw)?)
}

pub fn save_profile(name: &str, s: &Session) -> Result<()> {
    std::fs::write(profile_path(name)?, serde_json::to_string_pretty(s)?)?;
    Ok(())
}

pub fn list_profiles() -> Vec<String> {
    if single_file().is_some() {
        return vec!["default".to_string()];
    }
    let Ok(dir) = base_dir().map(|d| d.join("profiles")) else { return vec![] };
    let Ok(entries) = std::fs::read_dir(dir) else { return vec![] };
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.strip_suffix(".json").map(String::from))
        .collect();
    names.sort();
    names
}

/// The active profile: explicit config default, else the sole profile, else none.
pub fn default_profile() -> Option<String> {
    if single_file().is_some() {
        return Some("default".to_string());
    }
    let profiles = list_profiles();
    if let Ok(raw) = std::fs::read_to_string(base_dir().ok()?.join("config.json")) {
        if let Ok(cfg) = serde_json::from_str::<serde_json::Value>(&raw) {
            if let Some(d) = cfg["default"].as_str() {
                if profiles.iter().any(|p| p == d) {
                    return Some(d.to_string());
                }
            }
        }
    }
    match profiles.as_slice() {
        [only] => Some(only.clone()),
        _ => None,
    }
}

pub fn set_default(name: &str) -> Result<()> {
    if single_file().is_some() {
        return Ok(());
    }
    let path = base_dir()?.join("config.json");
    std::fs::write(path, serde_json::to_string_pretty(&serde_json::json!({ "default": name }))?)?;
    Ok(())
}

pub fn remove_profile(name: &str) -> Result<()> {
    std::fs::remove_file(profile_path(name)?)?;
    Ok(())
}

/// Split a path argument into (profile override, locator). A leading `alias:` is
/// only treated as a profile when `alias` is a known profile name; full `http(s)://`
/// URLs and ordinary relative paths pass through untouched.
pub fn parse_locator<'a>(raw: &'a str, known: &[String]) -> (Option<String>, &'a str) {
    if raw.starts_with("http://") || raw.starts_with("https://") {
        return (None, raw);
    }
    if let Some((maybe, rest)) = raw.split_once(':') {
        let valid = !maybe.is_empty()
            && maybe.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
        if valid && known.iter().any(|p| p == maybe) {
            return (Some(maybe.to_string()), rest);
        }
    }
    (None, raw)
}

pub fn resolve(base: &str, path: &str) -> String {
    if path.starts_with("http://") || path.starts_with("https://") {
        path.to_string()
    } else {
        format!("{}/{}", base.trim_end_matches('/'), path.trim_start_matches('/'))
    }
}

/// Pull child IRIs out of `ldp:contains` statements without a full Turtle parser.
/// After the predicate, read `<...>` IRIs separated only by whitespace/commas;
/// stop at the next `;`/`.` or other token. Dots inside IRIs (file extensions!)
/// don't terminate the object list.
pub fn parse_contains(ttl: &str) -> Vec<String> {
    let norm = ttl.replace("<http://www.w3.org/ns/ldp#contains>", "ldp:contains");
    let bytes = norm.as_bytes();
    let mut out = Vec::new();
    let mut search = 0;
    while let Some(rel) = norm[search..].find("ldp:contains") {
        let mut i = search + rel + "ldp:contains".len();
        loop {
            while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r' | b',') {
                i += 1;
            }
            if i < bytes.len() && bytes[i] == b'<' {
                if let Some(close_rel) = norm[i + 1..].find('>') {
                    let close = i + 1 + close_rel;
                    out.push(norm[i + 1..close].to_string());
                    i = close + 1;
                    continue;
                }
            }
            break; // hit ';', '.', or anything that isn't another IRI
        }
        search = i;
    }
    out
}

pub fn guess_type(url: &str) -> String {
    let ext = url.rsplit('.').next().unwrap_or("");
    match ext {
        "ttl" => "text/turtle",
        "json" => "application/json",
        "jsonld" => "application/ld+json",
        "txt" => "text/plain",
        "html" | "htm" => "text/html",
        "md" => "text/markdown",
        "csv" => "text/csv",
        _ => "application/octet-stream",
    }.to_string()
}

pub fn urlenc(s: &str) -> String {
    s.bytes().map(|b| match b {
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
        _ => format!("%{:02X}", b),
    }).collect()
}

pub fn urldec(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                if let Ok(h) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(h);
                    i += 3;
                    continue;
                }
                out.push(b'%');
                i += 1;
            }
            b'+' => { out.push(b' '); i += 1; }
            c => { out.push(c); i += 1; }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    #[test]
    fn dpop_is_valid_es256_with_claims() {
        let key = DpopKey::generate();
        let jwt = key.proof("GET", "https://pod/x", Some("tok")).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);

        let header: serde_json::Value =
            serde_json::from_slice(&B64.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header["typ"], "dpop+jwt");
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["jwk"]["crv"], "P-256");

        let payload: serde_json::Value =
            serde_json::from_slice(&B64.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(payload["htm"], "GET");
        assert_eq!(payload["htu"], "https://pod/x");
        assert_eq!(payload["ath"], s256("tok")); // bound to access token

        // signature verifies against the embedded public key
        let sig = Signature::from_slice(&B64.decode(parts[2]).unwrap()).unwrap();
        let vk = VerifyingKey::from(&key.0); // same-crate test reaches the inner key
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        assert!(vk.verify(signing_input.as_bytes(), &sig).is_ok());
    }

    #[test]
    fn no_ath_without_token() {
        let key = DpopKey::generate();
        let jwt = key.proof("POST", "https://idp/token", None).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&B64.decode(jwt.split('.').nth(1).unwrap()).unwrap()).unwrap();
        assert!(payload.get("ath").is_none());
    }

    #[test]
    fn pkce_challenge_is_sha256_of_verifier() {
        // S256: challenge == base64url(sha256(verifier))
        assert_eq!(s256("abc"), "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0");
    }

    #[test]
    fn resolve_relative_and_absolute() {
        assert_eq!(resolve("http://h/test", "a.ttl"), "http://h/test/a.ttl");
        assert_eq!(resolve("http://h/test/", "/a.ttl"), "http://h/test/a.ttl");
        assert_eq!(resolve("http://h/test", "https://other/x"), "https://other/x");
    }

    #[test]
    fn parse_contains_extracts_children() {
        let ttl = r#"
            @prefix ldp: <http://www.w3.org/ns/ldp#> .
            <http://h/test/> a ldp:Container ;
                ldp:contains <http://h/test/a.ttl>, <http://h/test/sub/> .
        "#;
        let kids = parse_contains(ttl);
        assert_eq!(kids, vec!["http://h/test/a.ttl", "http://h/test/sub/"]);
    }

    #[test]
    fn parse_contains_handles_full_iri_predicate() {
        let ttl = "<#> <http://www.w3.org/ns/ldp#contains> <http://h/test/x> .";
        assert_eq!(parse_contains(ttl), vec!["http://h/test/x"]);
    }

    #[test]
    fn guess_type_by_ext() {
        assert_eq!(guess_type("http://h/a.ttl"), "text/turtle");
        assert_eq!(guess_type("http://h/a.json"), "application/json");
        assert_eq!(guess_type("http://h/blob"), "application/octet-stream");
    }

    #[test]
    fn url_roundtrip() {
        let s = "a b/c?d=e&f";
        assert_eq!(urldec(&urlenc(s)), s);
    }

    #[test]
    fn locator_parsing() {
        let known = vec!["work".to_string(), "perso".to_string()];
        // known alias prefix -> split off
        assert_eq!(parse_locator("work:notes/x.md", &known), (Some("work".into()), "notes/x.md"));
        assert_eq!(parse_locator("perso:", &known), (Some("perso".into()), ""));
        // bare path -> no profile
        assert_eq!(parse_locator("notes/x.md", &known), (None, "notes/x.md"));
        // unknown alias is treated as a plain path, not a profile
        assert_eq!(parse_locator("bogus:x", &known), (None, "bogus:x"));
        // full URLs pass through even though they contain ':'
        assert_eq!(parse_locator("https://h/p/x", &known), (None, "https://h/p/x"));
    }
}
