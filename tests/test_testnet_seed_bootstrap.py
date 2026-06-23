from tools import testnet_seed_bootstrap


def _args(*extra):
    return testnet_seed_bootstrap.parse_args(
        [
            "--repo-dir",
            "/opt/international-dollar",
            "--runtime-dir",
            "/var/lib/ind-node",
            "--web-root",
            "/var/www/ind-testnet-mirror",
            "--operator-set",
            "testnet/operator_set.testnet.json",
            "--peer",
            "seed-a.example.test",
            "--peer",
            "108.61.23.82",
            "--public-host",
            "108.61.23.82",
            "--convergence-peer",
            "seed-a.example.test",
            "--convergence-peer",
            "108.61.23.82",
            "--canary-ref",
            "1x1782156155",
            *extra,
        ]
    )


def _file(files, suffix):
    matches = [item for item in files if item.path.endswith(suffix)]
    assert len(matches) == 1
    return matches[0]


def test_start_pre_clears_runtime_kill_flag():
    text = testnet_seed_bootstrap.render_start_pre("/var/lib/ind-node", "/opt/ind", "ind-node")

    assert "export IND_NETWORK=testnet" in text
    assert "install -d -m 750 -o ind-node -g ind-node /var/lib/ind-node" in text
    assert "chown -R ind-node:ind-node /var/lib/ind-node" in text
    assert "find /var/lib/ind-node -type d -exec chmod 750 {} +" in text
    assert "find /var/lib/ind-node -type f -exec chmod u+rw,go-rwx {} +" in text
    assert "runtime.ensure_runtime_files()" in text
    assert "runtime.set_kill_node(False)" in text


def test_filters_self_from_on_box_convergence_peers():
    peers = testnet_seed_bootstrap.filter_self_peers(
        ["seed-a.example.test", "108.61.23.82", "[2001:db8::1]"],
        ["108.61.23.82", "2001:db8::1"],
    )

    assert peers == ["seed-a.example.test"]


def test_generated_seed_service_has_runtime_guard_and_no_append_service():
    files = testnet_seed_bootstrap.generated_files(_args())
    seed_service = _file(files, "ind-testnet-seed-node.service").text
    node_env = _file(files, "ind-testnet-node.env").text
    nginx_site = _file(files, "ind-testnet-mirror").text

    assert "ExecStartPre=/usr/local/bin/ind-testnet-node-start-pre" in seed_service
    assert "ExecStart=/opt/international-dollar/.venv/bin/python /opt/international-dollar/node_client.py" in seed_service
    assert "IND_IGNORE_RUNTIME_KILL_FLAG=1" in node_env
    assert "transparency" not in seed_service.lower()
    assert "location ^~ /operator-api/" in nginx_site
    assert "return 404;" in nginx_site


def test_monitor_runs_as_root_retries_and_skips_self_peer():
    files = testnet_seed_bootstrap.generated_files(_args())
    monitor = _file(files, "ind-testnet-primary-monitor.service").text

    assert "User=ind-node" not in monitor
    assert "Environment=IND_NETWORK=testnet" in monitor
    assert "--retry-count 3" in monitor
    assert "--retry-delay-seconds 20" in monitor
    assert "--convergence-peer seed-a.example.test" in monitor
    assert "--convergence-peer 108.61.23.82" not in monitor


def test_local_verify_checks_port_mirrors_and_absent_operator_api():
    text = testnet_seed_bootstrap.render_local_verify(_args())

    assert "18888" in text
    assert "operator-api" in text
    assert 'test "$operator_api_status" = "404"' in text
    assert "/transparency/latest.json" in text
    assert "/iotb-operator/transparency/latest.json" in text
