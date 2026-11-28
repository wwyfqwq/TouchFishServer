from itertools import product

import config_utils
import web


def test_single_feature_lookup_matches_fully_materialized_settings():
    paths = [(), ("chat",), ("unknown",), ("forum", "nested"), ("chat", "missing")]
    for group, default in config_utils.FEATURE_DEFAULTS.items():
        if isinstance(default, dict):
            paths.extend((group, k) for k in default)
        else:
            paths.append((group,))
    for group, nested in product([False, None, 1, "bad", True], repeat=2):
        cfg = {"features": {"forum": group, "unknown": False, "chat": {"private_chat": nested}}}
        for path in paths:
            expected = config_utils.get_features(cfg)
            for part in path:
                expected = expected.get(part) if isinstance(expected, dict) else None
            assert config_utils.feature_gate(cfg, *path) == (expected if isinstance(expected, bool) else True)


def test_user_rate_buckets_expire_independently_in_last_accept_order(monkeypatch):
    clock = [100]
    monkeypatch.setattr(web.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(web, "_rate_limit_hits", {})
    for uid in range(5000):
        assert web.check_rate_limit(uid, "short", 1, 5)
    assert web.check_rate_limit(0, "long", 1, 20)
    assert not web.check_rate_limit(2, "short", 1, 5)
    clock[0] += 5
    assert web.check_rate_limit(1, "short", 1, 5)
    assert len(web._rate_limit_hits["short"]) == 1
    assert not web.check_rate_limit(0, "long", 1, 20)
    clock[0] += 15
    assert web.check_rate_limit(0, "long", 1, 20)
