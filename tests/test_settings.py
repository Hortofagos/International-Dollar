from ind import settings as ind_settings


def test_mainnet_defaults_use_live_operator_and_peer_config(monkeypatch):
    monkeypatch.delenv("IND_REQUIRE_TRANSPARENCY_LOG", raising=False)
    monkeypatch.delenv("IND_SUBMIT_TO_TRANSPARENCY_LOG", raising=False)
    monkeypatch.delenv("IND_ALLOW_UNTRUSTED_GENESIS", raising=False)

    settings = ind_settings.normalize_security_settings({})

    assert settings["network"] == "mainnet"
    assert settings["node_port"] == 8888
    assert settings["dns_seed_hosts"] == [
        "seed.international-dollar.com",
        "seed.internetofthebots.com",
    ]
    assert "seed.linkifier.me" not in settings["dns_seed_hosts"]
    assert settings["peer_ping_servers"] == [
        "seed.international-dollar.com",
        "seed.internetofthebots.com",
        "51.83.199.25",
    ]
    assert settings["trusted_root_domains"] == [
        "international-dollar.com",
        "internetofthebots.com",
        "91.99.175.174",
        "108.61.23.82",
    ]
    assert ind_settings.trusted_root_mirrors(settings) == [
        "http://91.99.175.174/mainnet-transparency",
        "http://108.61.23.82/mainnet-transparency",
    ]
    assert settings["transparency_operators"] == [
        {
            "url": "http://167.233.115.216/mainnet-operator-api",
            "public_key": "indpk3:Qu)F<E@Jz(MQ6iS8NLT+N-tt-O3|`^z6CsWx{Br7",
            "mirrors": [
                "http://91.99.175.174/mainnet-transparency",
                "http://108.61.23.82/mainnet-transparency",
            ],
            "proof_archives": [
                "http://91.99.175.174/mainnet-transparency",
                "http://108.61.23.82/mainnet-transparency",
            ],
        },
        {
            "url": "https://testnet-seed.internetofthebots.com/mainnet-iotb-operator-api",
            "public_key": "indpk3:i8x(A2B9u``X1Ny>r2)2`evenV>4H=Pz~{&*%j`u",
            "mirrors": [
                "https://international-dollar.com/mainnet-iotb-operator/transparency",
                "http://108.61.23.82/mainnet-iotb-operator/transparency",
            ],
            "proof_archives": [
                "https://international-dollar.com/mainnet-iotb-operator/transparency",
                "http://108.61.23.82/mainnet-iotb-operator/transparency",
            ],
        }
    ]
    production_settings = dict(settings, security_profile="production")
    assert not ind_settings.production_security_issues(production_settings)


def test_testnet_defaults_use_live_operator_and_peer_config():
    settings = ind_settings.normalize_security_settings({"network": "testnet"})

    assert settings["node_port"] == 18888
    assert settings["dns_seed_hosts"] == [
        "testnet-seed.international-dollar.com",
        "testnet-seed.internetofthebots.com",
    ]
    assert settings["peer_ping_servers"] == [
        "testnet-seed.international-dollar.com",
        "testnet-seed.internetofthebots.com",
        "51.83.199.25",
        "108.61.23.82",
    ]
    assert settings["trusted_root_domains"] == [
        "international-dollar.com",
        "internetofthebots.com",
        "167.233.115.216",
        "91.99.175.174",
    ]
    assert [operator["url"] for operator in settings["transparency_operators"]] == [
        "https://testnet-seed.international-dollar.com/operator-api",
        "https://testnet-seed.internetofthebots.com/operator-api",
        "http://108.61.23.82/operator-api",
    ]
    assert settings["trusted_genesis_manifest_hashes"] == [
        "9d1a9cfeb6ceefa4aa39b702af1f5c6be204ddd5fb2e8dd1df0041a47dd31aa6"
    ]


def test_custom_mirror_config_can_still_leave_root_domain_allowlist_empty():
    settings = ind_settings.normalize_security_settings(
        {
            "trusted_root_domains": [],
            "trusted_root_mirrors": ["http://example.invalid/transparency"],
        }
    )

    assert settings["trusted_root_domains"] == []
    assert ind_settings.trusted_root_mirrors(settings) == [
        "http://example.invalid/transparency"
    ]


def test_testnet_network_migrates_legacy_mainnet_baked_defaults():
    settings = ind_settings.normalize_security_settings(
        {
            "network": "testnet",
            "node_port": 8888,
            "peer_ping_servers": ["91.99.175.174", "51.83.199.25", "108.61.23.82"],
            "dns_seed_hosts": [
                "seed.international-dollar.com",
                "seed.linkifier.me",
                "seed.internetofthebots.com",
            ],
            "trusted_root_mirrors": [],
            "transparency_proof_archives": [],
            "transparency_operator_url": "",
            "transparency_operator_public_key": "",
            "transparency_operators": [],
            "trusted_genesis_issuer_keys": [],
            "trusted_genesis_manifest_hashes": [],
        }
    )

    assert settings["node_port"] == 18888
    assert settings["dns_seed_hosts"] == [
        "testnet-seed.international-dollar.com",
        "testnet-seed.internetofthebots.com",
    ]
    assert [operator["url"] for operator in settings["transparency_operators"]] == [
        "https://testnet-seed.international-dollar.com/operator-api",
        "https://testnet-seed.internetofthebots.com/operator-api",
        "http://108.61.23.82/operator-api",
    ]


def test_load_security_settings_honors_env_network_before_defaults(tmp_path, monkeypatch):
    monkeypatch.setenv("IND_NETWORK", "testnet")

    settings = ind_settings.load_security_settings(
        tmp_path / "missing-security-settings.json",
        validate_production=False,
    )

    assert settings["network"] == "testnet"
    assert settings["node_port"] == 18888
    assert settings["peer_ping_servers"] == [
        "testnet-seed.international-dollar.com",
        "testnet-seed.internetofthebots.com",
        "51.83.199.25",
        "108.61.23.82",
    ]


def test_auto_sync_on_wallet_sign_in_defaults_enabled():
    settings = ind_settings.normalize_security_settings({})

    assert settings["auto_sync_on_wallet_sign_in"] is True
    assert ind_settings.auto_sync_on_wallet_sign_in(settings) is True


def test_auto_sync_on_wallet_sign_in_can_be_disabled():
    settings = ind_settings.normalize_security_settings({"auto_sync_on_wallet_sign_in": "no"})

    assert settings["auto_sync_on_wallet_sign_in"] is False
    assert ind_settings.auto_sync_on_wallet_sign_in(settings) is False


def test_auto_sync_on_wallet_sign_in_env_override(monkeypatch):
    settings = ind_settings.normalize_security_settings({"auto_sync_on_wallet_sign_in": False})

    monkeypatch.setenv("IND_AUTO_SYNC_ON_WALLET_SIGN_IN", "yes")

    assert ind_settings.auto_sync_on_wallet_sign_in(settings) is True


def test_gui_scale_defaults_to_auto():
    settings = ind_settings.normalize_security_settings({})

    assert settings["gui_scale"] == "auto"
    assert ind_settings.gui_scale(settings) == "auto"


def test_gui_scale_accepts_selector_values():
    assert ind_settings.normalize_security_settings({"gui_scale": "1x"})["gui_scale"] == "1.0"
    assert ind_settings.normalize_security_settings({"gui_scale": "1.25x"})["gui_scale"] == "1.25"
    assert ind_settings.normalize_security_settings({"gui_scale": "1.5"})["gui_scale"] == "1.5"
    assert ind_settings.normalize_security_settings({"gui_scale": "2.0x"})["gui_scale"] == "2.0"


def test_gui_scale_rejects_unknown_values():
    settings = ind_settings.normalize_security_settings({"gui_scale": "3x"})

    assert settings["gui_scale"] == "auto"
