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
Logged in as 'default'. Profile at ~/.config/solid/profiles/default.json
```

`login` runs OIDC discovery against the issuer, registers a client dynamically, opens the
authorization URL in your browser, and catches the redirect on `http://localhost:9876/callback`.
The resulting DPoP-bound token (and a persisted P-256 key) are written to the profile and
refreshed automatically when expired.

### Profiles

Log in to several pods and address them explicitly — no hidden "current pod" that mutates under
you. `alias:path` (rclone style) selects a profile per command; the `--profile` flag does the
same; a bare path falls back to the default profile.

```sh
solid login --as work          # log in, store as profile "work"
solid login --as perso         # a second pod
solid profiles                 # list profiles (default marked with *)
solid use work                 # set the default profile
solid logout perso             # remove a profile

solid ls work:/                # explicit: profile "work"
solid cat perso:notes/x.md     # explicit: profile "perso"
solid -p perso ls /            # same, via flag
solid cat notes/x.md           # bare path -> default profile
```

Precedence: inline `alias:` > `--profile` flag > default. The first profile you create becomes the
default.

### Paths

A path is resolved against the pod base of the selected profile, or you can pass a full URL (it
still authenticates with the selected profile's identity):

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

## Storage

Profiles live in `~/.config/solid/profiles/<name>.json`; the default is recorded in
`~/.config/solid/config.json`. Each profile holds the access token, refresh token, and DPoP key.
Override the config directory with `$SOLID_CONFIG_DIR`, or point `$SOLID_SESSION` at a single file
to run in one-profile mode. `solid logout` (or deleting the file) removes a profile.

## Testing

```sh
cargo test                 # unit tests + end-to-end
cargo test -- --nocapture  # with server logs
```

Unit tests cover DPoP proof generation (real ES256 signature verification), PKCE, profile
addressing, and the Turtle container parser. The end-to-end tests spin up a real [Community Solid
Server](https://github.com/CommunitySolidServer/CommunitySolidServer) via `npx`, provision throwaway
pods, mint DPoP-bound tokens, and drive the compiled binary through put → ls → cat → rm — including
a two-profile run that checks `alias:path` / `--profile` routing and pod isolation. They skip
cleanly if `npx` is unavailable.

## Scope

LDP CRUD only — the five commands above. The interactive browser consent step of `login` is not
covered by automated tests; everything else, including DPoP-signed requests, is.

## License

MIT — see [LICENSE](LICENSE).
