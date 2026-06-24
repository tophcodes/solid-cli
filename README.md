# solid

A small, fast CLI for LDP CRUD over [Solid](https://solidproject.org/) pods. Log in with Solid-OIDC, then `ls`/`cat`/`put`/`rm` resources like a remote filesystem.

No Node, no Inrupt libraries — a single Rust binary that speaks the standards directly: OIDC Discovery, Dynamic Client Registration, Authorization Code + PKCE, and DPoP-bound tokens.

## Install

```sh
cargo build --release
# binary at target/release/solid
```

## Usage

```sh
solid login              # interactive OIDC login, opens a browser
solid ls /               # list a container
solid cat notes/todo.md  # print a resource to stdout
solid put notes/todo.md  # write/overwrite from stdin
solid rm  notes/todo.md  # delete
```

### Login

```
$ solid login
Issuer (OIDC provider) [https://solidcommunity.net]:
Pod base URL [https://solidcommunity.net]: https://you.solidcommunity.net
Opening browser…
Logged in. Session at ~/.config/solid/session.json
```

`login` runs OIDC discovery against the issuer, registers a client dynamically, opens the
authorization URL in your browser, and catches the redirect on `http://localhost:9876/callback`.
The resulting DPoP-bound token (and a persisted P-256 key) are written to the session file and
refreshed automatically when expired.

### Paths

A path is resolved against the pod base from `login`, or you can pass a full URL:

```sh
solid ls /public/
solid cat profile/card
solid cat https://other.example/pod/file.ttl
```

`put` guesses `Content-Type` from the extension (`.ttl`, `.json`, `.md`, …); override with `-t`:

```sh
echo '<#me> a <#Person>.' | solid put profile/me.ttl
cat photo.png | solid put album/photo.png -t image/png
```

## Compatibility

Works with any Solid-OIDC provider that offers **Dynamic Client Registration** (RFC 7591) —
Community Solid Server, Inrupt ESS, Node Solid Server, and others. The CLI itself contains no
server-specific code; it speaks only OIDC and LDP.

## Session

Stored at `~/.config/solid/session.json` (override with `$SOLID_SESSION`). Contains the access
token, refresh token, and the DPoP key. Delete the file to log out.

## Testing

```sh
cargo test                 # unit tests + end-to-end
cargo test -- --nocapture  # with server logs
```

Unit tests cover DPoP proof generation (real ES256 signature verification), PKCE, and the Turtle
container parser. The end-to-end test spins up a real [Community Solid
Server](https://github.com/CommunitySolidServer/CommunitySolidServer) via `npx`, provisions a
throwaway pod, mints a DPoP-bound token, and drives the compiled binary through put → ls → cat →
rm. It skips cleanly if `npx` is unavailable.

## Scope

LDP CRUD only — the five commands above. The interactive browser consent step of `login` is not
covered by automated tests; everything else, including DPoP-signed requests, is.

## License

MIT — see [LICENSE](LICENSE).
