from lanwatch import lanwatch as lw


def test_dev_uid_normalizes_mac():
    assert lw.dev_uid("AA:BB:CC:DD:EE:FF") == "lan_aabbccddeeff"


def test_disc_topics_uses_prefixes():
    uid = "lan_abcdef"
    cfg, state, attrs, cmd = lw.disc_topics(uid)

    assert cfg.startswith(f"{lw.DISC_PREFIX}/device_tracker/lan/{uid}/")
    assert state == f"{lw.TOP_PREFIX}/devices/{uid}/state"
    assert attrs == f"{lw.TOP_PREFIX}/devices/{uid}/attrs"
    assert cmd == f"{lw.TOP_PREFIX}/control/{uid}/scan" 