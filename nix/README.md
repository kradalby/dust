# Headscale integration test

Run on Linux with `/dev/kvm` available to the Nix builder:

```sh
nix build .#checks.x86_64-linux.headscale --no-link -L
```

The check boots the actual Dust release through `nixosModules.default`, including
its packaged Go sidecar, unprivileged user, persistent directories and service
hardening. Local release RPC drives the same `Dust.Bridge` API as the application;
it uses the fixed distribution port because Dust deliberately replaces EPMD.
A small HTTP payload service supplies observable bytes for EXPOSE and PROXY.
Only random inbound UDP ports are opened on the Dust test VMs for direct tsnet
transport; the production module's firewall defaults are unchanged.
The fixture explicitly sets `TS_DISABLE_NETNS=1` so unprivileged tsnet can reach
the test VLAN. Production defaults retain interface binding and `ALL_PROXY`
SOCKS support; disabling netns also disables that proxy support.

Headscale is pinned to a published revision exporting `testkit` and
`testkit-peer`. Its nixpkgs stays independent: Headscale requires newer Go than
Dust's pin. Auth keys are generated inside the VMs, not placed in the Nix store.
The fixture uses `http://headscale`, local `alice@`/`bob@` policy identities and
region 999's test-only self-signed DERP. Dust's client is Go tsnet; Rust's
`insecure-keyfetch`/`insecure-derp` feature flags do not apply.

## Coverage

- Auth keys, interactive control-provided auth URLs, invalid keys and rejection
  when interactive authentication cannot grant the requested tag.
- Real WhoIs identity and matching tags on exposed TCP ports and bootstrap
  port 9473. An authorized request accompanies denial checks.
- PEERS and RESOLVE include matching tagged nodes and exclude other tags;
  nonexistent names fail explicitly.
- EXPOSE inbound traffic and loopback-only PROXY outbound traffic over direct
  paths and forced DERP, with transport evidence from tailscaled.
- JOIN transfers the unlocked key and cookie; the normal runtime join consumer
  adopts them and serves the new pair to another invitee, including a
  same-master/new-cookie join. Locked joins defer serving until unlock. The joined client
  preserves its adopted key and cookie after restart. Adoption enables a real
  Erlang distribution RPC over the automatically exposed port 9000.
- Wrong, malformed and replayed invitation tokens; malformed JOIN commands and
  stalled bootstrap peers return without blocking subsequent sidecar commands.
  JOIN rejects tokens other than 32 bytes before dialing and bounds the whole
  exchange to ten seconds. Wrong-tag callers cannot consume a valid invitation.
  Key-store locking closes port 9473 and revokes
  pending invitations. Unlock restores service without restoring old tokens.
- Restart without an auth key preserves the tailnet IP and encrypted key store,
  starts locked, and loses outstanding invitations. Control outages leave
  established direct traffic usable; relay traffic recovers with control.
- Live ACL changes deny bootstrap traffic while HTTP remains allowed, then
  restore access. Missing local listeners fail while another exposure works.
- A root-only configured genesis cookie authenticates explicit local RPC;
  wrong and launcher-default cookies fail. Persisted/joined state wins over
  changed bootstrap credentials, and boot JOIN wins over configured genesis.
  Initial and detached deferred setup errors are tied to the failed BEAM PID
  and credential diagnostic, followed by valid-source recovery. Managed stop
  exercises graceful SIGTERM shutdown. Unconfigured fresh nodes keep independent
  random cookies.
- Go unit tests exercise expired invitations, absent WhoIs identity, untagged
  and mismatched identities, and replay. Controlled LocalAPI subprocess tests
  verify that missing or mismatched granted tags terminate Dust; Headscale
  rejects unauthorized requested tags before that post-authentication check.
  Expiry uses the real monotonic clock;
  advancing a VM's wall clock would not test it correctly.

The standalone sidecar parses `TS_TAGS`; the daemon currently overrides that
variable from its `:dust_bridge, :ts_tags` application setting (default
`tag:dust-node`). The fixture does not claim the documented daemon environment
override works. Unit tests cover comma-separated tags and exact intersection.

Dust consumes no application grants, capability map, Tailscale Serve/Funnel,
SSH or application HTTPS certificate API. Its permissions combine tailnet
packet ACLs, exact tag intersection and one-use bootstrap tokens. Port 4369 is
requested by setup, but the custom EPMD module does not run an EPMD listener;
the tested distribution route uses port 9000.

The local fixture cannot reproduce hosted Tailscale browser login, device
approval, tag-owner administration or public DERP infrastructure. It validates
Headscale's corresponding local auth/tag/relay contract. In particular,
`captureAuthURL`'s log fallback remains specific to `login.tailscale.com`;
Headscale login relies on the authoritative LocalAPI `AuthURL` instead. The
fixture's TLS certificate belongs to control/DERP, not application HTTPS.
Public ACME issuance and successful cloud Funnel are not tested. Credential
failure checks prove fail-stop after setup selects an invalid credential, not
absence of the launcher-default-cookie interval before asynchronous setup.
Explicit-cookie RPC probes do not prove automatic release RPC cookie discovery.
This test does not claim end-to-end encrypted file storage or UI coverage.
