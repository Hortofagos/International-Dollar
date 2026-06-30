import json

from tools import testnet_peers


def test_default_testnet_peer_args_include_direct_seed_peers():
    peers = testnet_peers.parse_peer_args(None)

    assert peers == [
        "testnet-seed.international-dollar.com",
        "testnet-seed.internetofthebots.com",
        "51.83.199.25",
        "108.61.23.82",
    ]


def test_testnet_peer_hosts_falls_back_to_dns_seed_hosts(tmp_path):
    config = tmp_path / "testnet.json"
    config.write_text(
        json.dumps(
            {
                "dns_seed_hosts": [
                    "testnet-seed.international-dollar.com",
                    "testnet-seed.internetofthebots.com",
                ]
            }
        ),
        encoding="utf-8",
    )

    assert testnet_peers.parse_peer_args(None, config_path=config) == [
        "testnet-seed.international-dollar.com",
        "testnet-seed.internetofthebots.com",
    ]
