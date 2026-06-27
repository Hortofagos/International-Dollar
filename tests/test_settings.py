from ind import settings as ind_settings


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
