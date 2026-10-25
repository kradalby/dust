{ pkgs, headscale, dustModule }:
let
  policy = acls: pkgs.writeText "dust-policy.json" (builtins.toJSON {
    tagOwners = {
      "tag:dust-node" = [ "alice@" ];
      "tag:other" = [ "alice@" ];
    };
    inherit acls;
  });
  allowAll = policy [{ action = "accept"; src = [ "*" ]; dst = [ "*:*" ]; }];
  httpOnly = policy [{ action = "accept"; src = [ "*" ]; dst = [ "*:8080" ]; }];
  payload = pkgs.runCommand "dust-transport-payload" { } ''
    mkdir -p $out
    printf 'dust transport test\n' > $out/index.html
    head -c 1048576 /dev/zero > $out/blob
  '';
  http = {
    systemd.services.payload = {
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        DynamicUser = true;
        ExecStart = "${pkgs.python3}/bin/python -m http.server 8080 --directory ${payload}";
      };
    };
  };
  peer = {
    imports = [ headscale.nixosModules.testkit-peer http ];
    environment.systemPackages = [ pkgs.curl pkgs.jq pkgs.python3 ];
    networking.firewall.trustedInterfaces = [ "tailscale0" ];
  };
  dust = { lib, config, ... }: {
    imports = [ dustModule http ];
    services.dust = {
      enable = true;
      package = pkgs.dust;
      nodeName = "dust@${config.networking.hostName}";
      environmentFile = "/run/dust.env";
      extraEnvironment = {
        TS_CONTROL_URL = "http://headscale";
        TS_DISABLE_NETNS = "1";
        TS_HOSTNAME = "dust-node-${config.networking.hostName}";
        TS_NO_LOGS_NO_SUPPORT = "1";
        ERL_FLAGS = "+S 2:2 +SDcpu 2 +SDio 2";
      };
    };
    systemd.services.dust.wantedBy = lib.mkForce [ ];
    environment.systemPackages = [ pkgs.curl pkgs.jq pkgs.python3 pkgs.procps ];
    # tsnet listens on a random UDP port; the production service stays unprivileged.
    networking.firewall.allowedUDPPortRanges = [{ from = 1024; to = 65535; }];
    virtualisation.memorySize = 2048;
  };
in
pkgs.testers.runNixOSTest {
  name = "dust-headscale";
  globalTimeout = 1800;
  nodes = {
    headscale = {
      imports = [ headscale.nixosModules.testkit ];
    };
    server = dust;
    client = {
      imports = [ dust ];
      services.dust.cookieFile = "/run/dust.cookie";
    };
    direct = peer;
    relay = {
      imports = [ peer ];
      systemd.services.tailscaled.environment.TS_DEBUG_ALWAYS_USE_DERP = "1";
    };
    outsider = peer;
  };
  testScript = ''
    import json
    import re
    import shlex

    T = 120

    def rpc_command(machine, expression, cookie=None):
        # Dust uses a fixed distribution port and no epmd daemon. RPC is local only.
        if cookie is None:
            cookie = machine.succeed(f"cat /var/lib/dust/ts_state/tsnet-state-{machine.name}/secrets.json").strip()
        code = 'IO.puts("RESULT:" <> Jason.encode!(' + expression + '))'
        command = (
            "runuser -u dust -- env HOME=/var/lib/dust DUST_DATA_DIR=/var/lib/dust "
            f"RELEASE_NODE=dust@{machine.name} RELEASE_COOKIE={shlex.quote(cookie)} "
            "ERL_AFLAGS='-erl_epmd_port 9000 -dist_listen false +S 2:2 +SDcpu 2 +SDio 2' "
            f"${pkgs.dust}/bin/dust rpc {shlex.quote(code)}"
        )
        return "timeout 40 " + command

    def rpc(machine, expression, cookie=None):
        output = machine.succeed(rpc_command(machine, expression, cookie))
        return json.loads(next(line[7:] for line in output.splitlines() if line.startswith("RESULT:")))

    def command(machine, text):
        return rpc(machine, "elem(Dust.Bridge.send_command(" + json.dumps(text) + ", 30000), 1)")

    def boot(machine, key=None, join=None, sidecar=True):
        machine.wait_for_unit("multi-user.target")
        machine.succeed("install -d -o dust -g dust -m 750 /var/lib/dust")
        machine.succeed("printf '%s\\n' " + shlex.quote("node_name: " + machine.name) + " > /var/lib/dust/config.yaml; chown dust:dust /var/lib/dust/config.yaml")
        environment = "TS_AUTHKEY=" + (key or "")
        if join is not None:
            environment += f"\nJOIN_IP={join[0]}\nJOIN_TOKEN={join[1]}"
        machine.succeed("printf '%s\\n' " + shlex.quote(environment) + " > /run/dust.env; chmod 600 /run/dust.env")
        machine.succeed("systemctl start dust")
        machine.wait_for_open_port(4884)
        machine.wait_until_succeeds(f"test -s /var/lib/dust/ts_state/tsnet-state-{machine.name}/secrets.json", timeout=T)
        if sidecar:
            assert rpc(machine, "Dust.Bridge.start_sidecar()") == "ok"

    def wait_status(machine, state):
        condition = '.network.state == "' + state + '"'
        if state == "needs_login":
            condition += ' and ((.network.auth_url // "") | startswith("http://headscale/"))'
        machine.wait_until_succeeds(
            'curl -fsS --max-time 5 -H "Authorization: Bearer $(cat /var/lib/dust/api_token)" '
            'http://127.0.0.1:4884/api/v1/status | jq -e ' + shlex.quote(condition),
            timeout=T,
        )

    def authenticated(machine):
        wait_status(machine, "authenticated")
        status = command(machine, "AUTH_STATUS")
        assert status.startswith("OK:authenticated|"), status
        return status.split("|")[1]

    def http_ok(ip):
        return f"curl -fsS --max-time 5 http://{ip}:8080/ | grep -x 'dust transport test'"

    def token_request(machine, ip, token, denied=False):
        if denied:
            cursor = server.succeed("journalctl -u dust -n 0 --show-cursor").split("-- cursor: ")[-1].strip()
            caller_ip = machine.succeed("tailscale ip -4").strip()
        script = (
            "import socket; "
            f"s=socket.create_connection(({ip!r},9473),5); s.settimeout(5); "
            f"s.sendall({token.encode()!r}); s.shutdown(socket.SHUT_WR); "
            "data=bytes()\n"
            "try:\n"
            " while chunk := s.recv(4096): data += chunk\n"
            "except ConnectionResetError:\n"
            f" if not {denied!r}: raise\n"
            "print(data.decode())"
        )
        response = machine.succeed("python -c " + shlex.quote(script)).strip()
        if denied:
            assert response in ("", "ERR: Peer is not a dust node"), response
            # Rejecting before reading the token can reset TCP; require the exact caller's denial log.
            message = "SERVE_SECRETS: rejected non-dust peer: " + caller_ip + ":"
            server.wait_until_succeeds(f"journalctl -u dust --after-cursor={shlex.quote(cursor)} -o cat | grep -F {shlex.quote(message)}", timeout=T)
        return response

    start_all()
    headscale.succeed("hs-authkey alice >/dev/null")
    headscale.succeed("headscale policy set -f ${allowAll}")
    key = headscale.succeed("hs-authkey alice --tags tag:dust-node").strip()
    other_key = headscale.succeed("hs-authkey alice --tags tag:other").strip()
    direct.succeed(f"hs-join {key} --hostname dust-node-direct")
    relay.succeed(f"hs-join {key} --hostname dust-node-relay")
    outsider.succeed(f"hs-join {other_key} --hostname dust-node-outsider")
    client.succeed("umask 077; python -c 'import secrets; print(secrets.token_hex(16))' > /run/dust.cookie")
    boot(server, key)
    boot(client, key)
    for machine in (server, client):
        machine.wait_until_succeeds("journalctl -u dust -o cat | grep -F 'TAG CHECK OK'", timeout=T)
    server_ip = authenticated(server)
    client_ip = authenticated(client)
    server_genesis_cookie = rpc(server, "Atom.to_string(Node.get_cookie())")

    with subtest("unprivileged service, local-only API and proxy"):
        server.succeed("test $(systemctl show dust -p User --value) = dust")
        server.succeed("test $(systemctl show dust -p NoNewPrivileges --value) = yes")
        server.succeed("test $(systemctl show dust -p ProtectSystem --value) = strict")
        server.succeed("grep -E '^CapEff:[[:space:]]+0000000000000000$' /proc/$(pgrep -u dust -x tsnet_sidecar)/status")
        server.succeed("ss -lnt | grep -F '127.0.0.1:4884'")
        server.succeed("test $(stat -c %a /var/lib/dust/api_token) = 640")
        server.fail("runuser -u nobody -- cat /var/lib/dust/api_token")
        server.succeed("test $(curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:4884/api/v1/config) = 401")
        server.succeed('curl -fsS --max-time 5 -H "Authorization: Bearer $(cat /var/lib/dust/api_token)" http://127.0.0.1:4884/api/v1/config >/dev/null')
        wait_status(server, "authenticated")
        direct.fail(f"curl -fsS --max-time 5 http://{server_ip}:4884/api/v1/status")
        assert command(server, "EXPOSE 8080") == "OK: exposed 8080"
        direct.wait_until_succeeds(http_ok(server_ip), timeout=T)

    with subtest("WhoIs tags and discovery, with live allowed controls"):
        peers = command(server, "PEERS").removeprefix("OK:").split(",")
        assert {"client", "direct", "relay"} <= set(peers), peers
        assert "outsider" not in peers, peers
        assert command(server, "RESOLVE client") == "OK:" + client_ip
        assert command(server, "RESOLVE outsider") == "ERR: peer not found"
        assert command(server, "RESOLVE missing") == "ERR: peer not found"
        outsider.fail(http_ok(server_ip))
        direct.succeed(http_ok(server_ip))
        server.wait_until_succeeds("journalctl -u dust -o cat | grep -F 'EXPOSE rejected non-dust peer'", timeout=T)

    with subtest("application traffic over direct and forced DERP"):
        direct.wait_until_succeeds(f"tailscale ping -c 1 --timeout 3s {server_ip}", timeout=T)
        direct.succeed(http_ok(server_ip))
        direct.succeed("tailscale status --json | jq -e '.Peer[] | select(.HostName == \"dust-node-server\") | .CurAddr != \"\"'")
        relay.wait_until_succeeds(f"tailscale ping --until-direct=false -c 1 --timeout 3s {server_ip} | grep -F 'via DERP(headscale)'", timeout=T)
        relay.succeed(http_ok(server_ip))
        for peer in (direct, relay):
            peer.succeed(f"curl -fsS --max-time 30 http://{server_ip}:8080/blob | cmp - ${payload}/blob")
            peer_ip = peer.succeed("tailscale ip -4").strip()
            port = int(command(server, f"PROXY {peer_ip}:8080").removeprefix("OK:"))
            server.succeed(f"ss -lnt | grep -F '127.0.0.1:{port}'")
            server.wait_until_succeeds(http_ok("127.0.0.1").replace(":8080/", f":{port}/"), timeout=T)
            server.succeed(f"curl -fsS --max-time 30 http://127.0.0.1:{port}/blob | cmp - ${payload}/blob")

    with subtest("bootstrap JOIN, WhoIs and single-use token enforcement"):
        assert rpc(server, 'Dust.Core.KeyStore.unlock("integration-password")') == "ok"
        token = "a" * 32
        assert command(server, "INVITE_CREATE " + token) == "OK: invite created"
        token_request(outsider, server_ip, token, denied=True)
        assert token_request(direct, server_ip, "short") == "ERR: Invalid token format"
        assert token_request(direct, server_ip, "b" * 32) == "ERR: Invalid or expired token"
        joined = command(client, f"JOIN {server_ip} {token}")
        assert joined.startswith("OK:") and ":" in joined[3:], joined
        assert command(client, f"JOIN {server_ip} {token}") == "ERR: server rejected: ERR: Invalid or expired token"
        command(server, "INVITE_CREATE " + "c" * 32)
        assert token_request(relay, server_ip, "c" * 32) == joined[3:]
        direct.succeed(http_ok(server_ip))

    with subtest("runtime join adopts and serves the cluster key and cookie"):
        master, cookie = joined[3:].split(":", 1)
        assert rpc(client, 'Dust.Core.KeyStore.unlock("client-password")') == "ok"
        assert rpc(client, "Base.encode64(elem(Dust.Core.KeyStore.get_key(), 1))") != master
        command(server, "INVITE_CREATE " + "4" * 32)
        assert rpc(client, "inspect(Dust.Daemon.Join.join(" + json.dumps(server_ip) + ", " + json.dumps("4" * 32) + "))") == "{:ok, :adopted}"
        assert rpc(client, "Base.encode64(elem(Dust.Core.KeyStore.get_key(), 1))") == master
        command(client, "INVITE_CREATE " + "5" * 32)
        assert token_request(direct, client_ip, "5" * 32) == joined[3:]
        server.wait_until_succeeds(
            "curl -fsS --max-time 5 http://127.0.0.1:4884/api/v1/status | "
            "jq -e '.peer_names | index(\"dust@client\")'", timeout=T,
        )
        assert rpc(server, 'Node.connect(:"dust@client")') is True
        assert rpc(server, ':rpc.call(:"dust@client", :erlang, :node, [])') == "dust@client"

    with subtest("same-master runtime join refreshes the served cookie"):
        cookie = rpc(server, "Base.encode16(:crypto.strong_rand_bytes(16), case: :lower)")
        assert rpc(server, "Dust.Bridge.Secrets.adopt_joined_secrets(" + json.dumps(master) + ", " + json.dumps(cookie) + ")") == "ok"
        assert rpc(server, "Dust.Core.KeyStore.lock()") == "ok"
        assert rpc(server, 'Dust.Core.KeyStore.unlock("integration-password")') == "ok"
        command(server, "INVITE_CREATE " + "0" * 32)
        assert rpc(client, "inspect(Dust.Daemon.Join.join(" + json.dumps(server_ip) + ", " + json.dumps("0" * 32) + "))") == "{:ok, :already_current}"
        assert rpc(client, "Atom.to_string(Node.get_cookie())") == cookie
        joined = "OK:" + master + ":" + cookie
        command(client, "INVITE_CREATE " + "5" * 32)
        assert token_request(direct, client_ip, "5" * 32) == joined[3:]

    with subtest("joined client preserves adopted secrets across restart"):
        client.succeed("umask 077; python -c 'import secrets; print(secrets.token_hex(16))' > /run/dust.cookie")
        cursor = client.succeed("journalctl -u dust -n 0 --show-cursor").split("-- cursor: ")[-1].strip()
        client.succeed("systemctl stop dust")
        client.succeed("test $(systemctl show dust -p Result --value) = success")
        client.succeed(f"journalctl -u dust --after-cursor={shlex.quote(cursor)} -o cat | grep -F 'SIGTERM received - shutting down'")
        client.succeed("printf 'TS_AUTHKEY=\\n' > /run/dust.env; systemctl start dust")
        client.wait_for_open_port(4884)
        assert authenticated(client) == client_ip
        assert rpc(client, "Dust.Core.KeyStore.has_key?()") is False
        assert rpc(client, 'Dust.Core.KeyStore.unlock("client-password")') == "ok"
        assert rpc(client, "Base.encode64(elem(Dust.Core.KeyStore.get_key(), 1))") == master
        command(client, "INVITE_CREATE " + "6" * 32)
        assert token_request(direct, client_ip, "6" * 32) == joined[3:]

    with subtest("malformed JOIN returns without blocking later commands"):
        for token in ("short", "x" * 33):
            assert command(client, f"JOIN {server_ip} {token}") == "ERR: invalid token length: want 32 bytes"
            assert command(client, "GET_STATUS") == "OK: running"
        command(server, "INVITE_CREATE " + "7" * 32)
        assert command(client, f"JOIN {server_ip} " + "7" * 32) == joined

    with subtest("stalled bootstrap peer cannot block later sidecar commands"):
        script = (
            "import socket,time; s=socket.socket(); s.bind(('0.0.0.0',9473)); s.listen(); "
            "c,_=s.accept(); c.recv(32); time.sleep(60)"
        )
        direct.succeed("systemd-run --unit=stalled-bootstrap python -c " + shlex.quote(script))
        direct.wait_until_succeeds("ss -lnt | grep -F ':9473 '", timeout=T)
        direct_ip = direct.succeed("tailscale ip -4").strip()
        response = command(client, f"JOIN {direct_ip} " + "8" * 32)
        assert response.startswith("ERR: failed to read secrets:") and "timeout" in response, response
        assert command(client, "GET_STATUS") == "OK: running"
        direct.succeed("systemctl stop stalled-bootstrap")

    with subtest("lock closes secrets and revokes pending invitations"):
        command(server, "INVITE_CREATE " + "d" * 32)
        assert rpc(server, "Dust.Core.KeyStore.lock()") == "ok"
        assert rpc(server, "Dust.Core.KeyStore.refresh_secrets()") == "ok"
        direct.fail(f"timeout 6 bash -c 'echo > /dev/tcp/{server_ip}/9473'")
        direct.succeed(http_ok(server_ip))
        assert rpc(server, 'Dust.Core.KeyStore.unlock("integration-password")') == "ok"
        assert token_request(direct, server_ip, "d" * 32) == "ERR: Invalid or expired token"
        command(server, "INVITE_CREATE " + "e" * 32)
        assert token_request(direct, server_ip, "e" * 32) == joined[3:]

    with subtest("restart preserves identity but not invitations or unlocked secrets"):
        command(server, "INVITE_CREATE " + "f" * 32)
        server.succeed("printf 'TS_AUTHKEY=\\n' > /run/dust.env; systemctl restart dust")
        server.wait_for_open_port(4884)
        direct.wait_until_succeeds(f"tailscale ping --until-direct=false -c 1 --timeout 3s {server_ip}", timeout=T)
        assert authenticated(server) == server_ip
        assert rpc(server, "Dust.Core.KeyStore.has_key?()") is False
        assert rpc(server, 'Dust.Core.KeyStore.unlock("integration-password")') == "ok"
        assert token_request(direct, server_ip, "f" * 32) == "ERR: Invalid or expired token"
        command(server, "INVITE_CREATE " + "1" * 32)
        assert token_request(direct, server_ip, "1" * 32) == joined[3:]
        command(server, "EXPOSE 8080")
        direct.wait_until_succeeds(http_ok(server_ip), timeout=T)

    with subtest("live ACL denial with allowed-operation control and recovery"):
        headscale.succeed("headscale policy set -f ${httpOnly}")
        direct.wait_until_fails(f"timeout 6 bash -c 'echo > /dev/tcp/{server_ip}/9473'", timeout=T)
        direct.succeed(http_ok(server_ip))
        relay.succeed(http_ok(server_ip))
        headscale.succeed("headscale policy set -f ${allowAll}")
        command(server, "INVITE_CREATE " + "2" * 32)
        direct.wait_until_succeeds(f"timeout 6 bash -c 'echo > /dev/tcp/{server_ip}/9473'", timeout=T)
        assert token_request(direct, server_ip, "2" * 32) == joined[3:]

    with subtest("exposed port with no local listener fails without taking down other traffic"):
        command(server, "EXPOSE 18080")
        direct.fail(f"curl -fsS --max-time 5 http://{server_ip}:18080/")
        direct.succeed(http_ok(server_ip))
        server.wait_until_succeeds("journalctl -u dust -o cat | grep -F 'EXPOSE dial local error'", timeout=T)

    with subtest("control outage preserves established application transport"):
        headscale.succeed("systemctl stop headscale")
        relay.fail(http_ok(server_ip))
        direct.succeed(http_ok(server_ip))
        headscale.succeed("systemctl start headscale")
        relay.wait_until_succeeds(http_ok(server_ip), timeout=T)

    with subtest("untagged peer cannot access exposed data or bootstrap secrets"):
        bob_key = headscale.succeed("hs-authkey bob").strip()
        outsider.succeed("tailscale logout; systemctl stop tailscaled; mv /var/lib/tailscale/tailscaled.state /var/lib/tailscale/tagged.state; systemctl start tailscaled")
        outsider.succeed(f"hs-join {bob_key} --hostname dust-node-untagged")
        outsider.succeed("tailscale status --json | jq -e '(.Self.Tags // []) | length == 0'")
        outsider.fail(http_ok(server_ip))
        command(server, "INVITE_CREATE " + "3" * 32)
        token_request(outsider, server_ip, "3" * 32, denied=True)
        assert "untagged" not in command(server, "PEERS").removeprefix("OK:").split(",")
        assert token_request(direct, server_ip, "3" * 32) == joined[3:]
        direct.succeed(http_ok(server_ip))

    with subtest("interactive auth uses control-provided URL, then validates tags"):
        # Reuse the client VM with fresh state. No hosted-login URL scraping is needed.
        client.succeed("systemctl stop dust; mv /var/lib/dust/ts_state /var/lib/dust/previous-ts-state")
        boot(client)
        wait_status(client, "needs_login")
        configured_cookie = client.succeed("cat /run/dust.cookie").strip()
        assert rpc(client, "Atom.to_string(Node.get_cookie())") == configured_cookie
        assert rpc(client, "Node.self()", configured_cookie) == "dust@client"
        for wrong_cookie in ("wrong-cookie", "dust_cookie"):
            client.fail(rpc_command(client, "Node.self()", wrong_cookie))
        assert rpc(client, "Node.self()", configured_cookie) == "dust@client"
        direct.succeed(http_ok(server_ip))
        status = command(client, "AUTH_STATUS")
        assert status.startswith("OK:needs_login|"), status
        assert "http://headscale/" in status, status
        match = re.search(r"hskey-authreq-[0-9a-f]+", status)
        assert match is not None, status
        auth_id = match.group()
        headscale.succeed(f"headscale auth register --user alice --auth-id {auth_id}")
        client.wait_until_succeeds("journalctl -u dust --since '1 minute ago' -o cat | grep -F 'TAG CHECK OK'", timeout=T)
        assert authenticated(client)

    with subtest("invalid auth key cannot join; existing authorized node remains usable"):
        client.succeed("systemctl stop dust; mv /var/lib/dust/ts_state /var/lib/dust/interactive-ts-state")
        cursor = client.succeed("journalctl -u dust -n 0 --show-cursor").split("-- cursor: ")[-1].strip()
        boot(client, "tskey-auth-invalid")
        # A bogus key must never reach Running. Wait for the control rejection first.
        client.wait_until_succeeds(f"journalctl -u dust --after-cursor={shlex.quote(cursor)} -o cat | grep -iE 'invalid.*(key|auth)|(key|auth).*invalid'", timeout=T)
        assert not command(client, "AUTH_STATUS").startswith("OK:authenticated|")
        direct.succeed(http_ok(server_ip))

    with subtest("control rejects interactive identity without tag ownership"):
        client.succeed("systemctl stop dust; mv /var/lib/dust/ts_state /var/lib/dust/invalid-ts-state")
        headscale.succeed("hs-authkey bob >/dev/null")
        boot(client)
        wait_status(client, "needs_login")
        status = command(client, "AUTH_STATUS")
        match = re.search(r"hskey-authreq-[0-9a-f]+", status)
        assert match is not None, status
        auth_id = match.group()
        rejection = headscale.fail(f"headscale auth register --user bob --auth-id {auth_id} 2>&1")
        assert "invalid or not permitted" in rejection, rejection
        assert not command(client, "AUTH_STATUS").startswith("OK:authenticated|")
        direct.succeed(http_ok(server_ip))

    with subtest("boot JOIN takes precedence over configured genesis cookie"):
        client.succeed("systemctl stop dust; mv /var/lib/dust/ts_state /var/lib/dust/rejected-ts-state")
        command(server, "INVITE_CREATE " + "9" * 32)
        boot(client, key, join=(server_ip, "9" * 32))
        assert authenticated(client)
        assert rpc(client, "Atom.to_string(Node.get_cookie())") == cookie
        assert rpc(client, "Dust.Bridge.Secrets.get_fetched_master_key()") == master
        assert rpc(client, "Node.self()", cookie) == "dust@client"
        direct.succeed(http_ok(server_ip))

    with subtest("blank bootstrap credential fails service startup"):
        client.succeed("systemctl stop dust; mv /var/lib/dust/ts_state /var/lib/dust/boot-joined-ts-state")
        client.succeed("mkdir -p /run/systemd/system/dust.service.d; printf '[Service]\\nRestart=no\\n' > /run/systemd/system/dust.service.d/credential-test.conf; systemctl daemon-reload")
        client.succeed("printf ' \\n' > /run/dust.cookie")
        client.succeed("printf '%s\\n' " + shlex.quote("TS_AUTHKEY=" + key) + " > /run/dust.env")
        cursor = client.succeed("journalctl -u dust -n 0 --show-cursor").split("-- cursor: ")[-1].strip()
        client.succeed("systemctl start dust")
        failed_pid = client.succeed("systemctl show dust -p ExecMainPID --value").strip()
        assert failed_pid != "0"
        client.wait_until_succeeds(f"journalctl -u dust _PID={failed_pid} --after-cursor={shlex.quote(cursor)} -o cat | grep -F 'DUST_COOKIE_FILE must contain 1-255 printable ASCII characters'", timeout=T)
        client.wait_until_succeeds("test $(systemctl show dust -p ExecMainStatus --value) = 1", timeout=T)
        client.fail(f"test -e /proc/{failed_pid}")
        client.fail(rpc_command(client, "Node.self()", "dust_cookie"))
        client.fail("test -e /var/lib/dust/ts_state/tsnet-state-client/secrets.json")
        direct.succeed(http_ok(server_ip))
        client.succeed("systemctl stop dust")

    with subtest("deferred sidecar setup also fails closed on invalid credentials"):
        client.succeed("mv /var/lib/dust/master.key /var/lib/dust/joined-master.key")
        client.succeed("umask 077; python -c 'import secrets; print(secrets.token_hex(16))' > /run/dust.cookie")
        boot(client, key, sidecar=False)
        assert rpc(client, "Dust.Bridge.sidecar_running?()") is False
        active_cookie = rpc(client, "Atom.to_string(Node.get_cookie())")
        client.succeed("printf ' \\n' > /var/lib/dust/blank.cookie; chmod 644 /var/lib/dust/blank.cookie")
        assert rpc(client, 'System.put_env("DUST_COOKIE_FILE", "/var/lib/dust/blank.cookie")') == "ok"
        client.succeed("rm /var/lib/dust/ts_state/tsnet-state-client/secrets.json")
        cursor = client.succeed("journalctl -u dust -n 0 --show-cursor").split("-- cursor: ")[-1].strip()
        failed_pid = client.succeed("systemctl show dust -p MainPID --value").strip()
        assert rpc(client, "Dust.Bridge.start_sidecar()", active_cookie) == "ok"
        client.wait_until_succeeds(f"journalctl -u dust _PID={failed_pid} --after-cursor={shlex.quote(cursor)} -o cat | grep -F 'DUST_COOKIE_FILE must contain 1-255 printable ASCII characters'", timeout=T)
        client.wait_until_succeeds("test $(systemctl show dust -p ExecMainStatus --value) = 1", timeout=T)
        client.fail(f"test -e /proc/{failed_pid}")
        client.fail(rpc_command(client, "Node.self()", "dust_cookie"))
        client.fail(rpc_command(client, "Node.self()", active_cookie))
        client.fail("test -e /var/lib/dust/ts_state/tsnet-state-client/secrets.json")
        direct.succeed(http_ok(server_ip))
        boot(client, key)
        assert authenticated(client)
        configured_cookie = client.succeed("cat /run/dust.cookie").strip()
        assert rpc(client, "Node.self()", configured_cookie) == "dust@client"
        client.fail(rpc_command(client, "Node.self()", "dust_cookie"))
        assert rpc(client, "Node.self()", configured_cookie) == "dust@client"

    with subtest("locked runtime join defers serving until unlock"):
        assert rpc(client, "Dust.Core.KeyStore.has_key?()") is False
        command(server, "INVITE_CREATE " + "8" * 32)
        assert rpc(client, "inspect(Dust.Daemon.Join.join(" + json.dumps(server_ip) + ", " + json.dumps("8" * 32) + "))") == "{:ok, :deferred}"
        assert rpc(client, "Dust.Core.KeyStore.has_key?()") is False
        client_ip = authenticated(client)
        direct.fail(f"timeout 6 bash -c 'echo > /dev/tcp/{client_ip}/9473'")
        assert rpc(client, 'Dust.Core.KeyStore.unlock("deferred-password")') == "ok"
        assert rpc(client, "Base.encode64(elem(Dust.Core.KeyStore.get_key(), 1))") == master
        command(client, "INVITE_CREATE " + "6" * 32)
        assert token_request(direct, client_ip, "6" * 32) == joined[3:]

    with subtest("unconfigured fresh state keeps independent random genesis cookies"):
        assert re.fullmatch(r"[0-9a-f]{32}", server_genesis_cookie), server_genesis_cookie
        server.succeed("systemctl stop dust; mv /var/lib/dust/ts_state /var/lib/dust/cluster-ts-state")
        boot(server, key)
        assert authenticated(server)
        fresh_cookie = rpc(server, "Atom.to_string(Node.get_cookie())")
        assert re.fullmatch(r"[0-9a-f]{32}", fresh_cookie), fresh_cookie
        assert fresh_cookie != server_genesis_cookie
        assert rpc(server, "Node.self()", fresh_cookie) == "dust@server"
        server.fail(rpc_command(server, "Node.self()", "dust_cookie"))
        assert rpc(server, "Node.self()", fresh_cookie) == "dust@server"
  '';
}
