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

/// Fresh P-256 DPoP keypair; returns the key and its base64url-encoded secret scalar.
pub fn gen_key() -> (SigningKey, String) {
    let key = SigningKey::random(&mut rand::rngs::OsRng);
    let b64 = B64.encode(key.to_bytes());
    (key, b64)
}

pub fn key_from_b64(b64: &str) -> Result<SigningKey> {
    let bytes = B64.decode(b64)?;
    Ok(SigningKey::from_bytes(bytes.as_slice().into())?)
}

/// Build a DPoP proof JWT for (method, url), optionally bound to an access token (ath).
pub fn dpop_proof(key: &SigningKey, method: &str, url: &str, token: Option<&str>) -> Result<String> {
    let pt = key.verifying_key().to_encoded_point(false);
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
    let sig: Signature = key.sign(signing_input.as_bytes());
    Ok(format!("{}.{}", signing_input, B64.encode(sig.to_bytes())))
}

pub fn apply_token(s: &mut Session, t: TokenResp) {
    s.access_token = t.access_token;
    s.expires_at = now() + t.expires_in.unwrap_or(3600).saturating_sub(30);
    if t.refresh_token.is_some() {
        s.refresh_token = t.refresh_token;
    }
}

/// Session file path. Honors `$SOLID_SESSION` (used by tests), else `~/.config/solid/session.json`.
pub fn config_path() -> Result<std::path::PathBuf> {
    if let Ok(p) = std::env::var("SOLID_SESSION") {
        let pb = std::path::PathBuf::from(p);
        if let Some(parent) = pb.parent() {
            std::fs::create_dir_all(parent)?;
        }
        return Ok(pb);
    }
    let dir = dirs::config_dir().ok_or_else(|| anyhow!("no config dir"))?.join("solid");
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join("session.json"))
}

pub fn load() -> Result<Session> {
    let raw = std::fs::read_to_string(config_path()?)
        .map_err(|_| anyhow!("not logged in — run `solid login`"))?;
    Ok(serde_json::from_str(&raw)?)
}

pub fn save(s: &Session) -> Result<()> {
    std::fs::write(config_path()?, serde_json::to_string_pretty(s)?)?;
    Ok(())
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
        let (key, _) = gen_key();
        let jwt = dpop_proof(&key, "GET", "https://pod/x", Some("tok")).unwrap();
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
        let vk = VerifyingKey::from(&key);
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        assert!(vk.verify(signing_input.as_bytes(), &sig).is_ok());
    }

    #[test]
    fn no_ath_without_token() {
        let (key, _) = gen_key();
        let jwt = dpop_proof(&key, "POST", "https://idp/token", None).unwrap();
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
}
