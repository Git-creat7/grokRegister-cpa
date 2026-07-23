# -*- coding: utf-8 -*-
import time
import unittest
from unittest.mock import patch

import protocol_pipeline as pp
import protocol_signup as ps


class ConfigCacheTests(unittest.TestCase):
    def setUp(self):
        ps.clear_config_cache()

    def tearDown(self):
        ps.clear_config_cache()

    def test_get_cached_config_reuses_within_ttl(self):
        fake = {
            "site_key": "0x4AAAAAAAhr9JGVTEST",
            "action_id": "a" * 40,
            "state_tree": "%5B%22%22%2C%7B%7D%5D",
        }
        with patch.object(ps.ProtocolClient, "fetch_config", return_value=fake) as m:
            a = ps.get_cached_config(proxy="")
            b = ps.get_cached_config(proxy="")
            self.assertEqual(a["site_key"], fake["site_key"])
            self.assertEqual(b["action_id"], fake["action_id"])
            self.assertEqual(m.call_count, 1)

    def test_force_refetch(self):
        fake1 = {
            "site_key": "0x4AAAAAAAhr9JGVTEST1",
            "action_id": "b" * 40,
            "state_tree": "tree1",
        }
        fake2 = {
            "site_key": "0x4AAAAAAAhr9JGVTEST2",
            "action_id": "c" * 40,
            "state_tree": "tree2",
        }
        with patch.object(
            ps.ProtocolClient, "fetch_config", side_effect=[fake1, fake2]
        ) as m:
            a = ps.get_cached_config(proxy="")
            b = ps.get_cached_config(proxy="", force=True)
            self.assertEqual(a["site_key"], fake1["site_key"])
            self.assertEqual(b["site_key"], fake2["site_key"])
            self.assertEqual(m.call_count, 2)


class RegisterOneParallelTests(unittest.TestCase):
    def test_register_one_runs_mint_and_mail_in_parallel(self):
        events = {"mint": 0.0, "mail": 0.0}

        def fake_mint(*a, **k):
            events["mint"] = time.time()
            time.sleep(0.15)
            return "cf-token-" + ("x" * 20)

        def fake_get_email():
            events["mail"] = time.time()
            time.sleep(0.15)
            return "u@example.com", "dev-token"

        def fake_get_code(*a, **k):
            return "123456"

        class FakeClient:
            def __init__(self, proxy="", user_agent=""):
                self.ua = user_agent or "ua"
                self.proxy = proxy

            def clear_auth_cookies(self):
                return None

            def create_email_code(self, email):
                return None

            def verify_email_code(self, email, code):
                return None

            def signup_server_action(self, body, action_id, state_tree):
                return "ok", "sso-token-value-xxxxxxxxxxxxxxxxxxxx"

            def fetch_config(self, should_stop=None):
                return {
                    "site_key": "0x4AAAAAAAhr9JGVTEST",
                    "action_id": "d" * 40,
                    "state_tree": "tree",
                }

        cfg = {
            "site_key": "0x4AAAAAAAhr9JGVTEST",
            "action_id": "d" * 40,
            "state_tree": "tree",
        }
        with patch.object(ps, "mint_turnstile", side_effect=fake_mint), patch.object(
            ps, "ProtocolClient", FakeClient
        ), patch.object(ps, "extract_sso_from_text", return_value=""):
            t0 = time.time()
            result = ps.register_one(
                get_email_and_token=fake_get_email,
                get_oai_code=fake_get_code,
                proxy="",
                cfg=cfg,
            )
            elapsed = time.time() - t0
        self.assertEqual(result["email"], "u@example.com")
        self.assertTrue(result["sso"])
        # 并行应明显小于串行 0.15+0.15
        self.assertLess(elapsed, 0.28)
        self.assertLess(abs(events["mint"] - events["mail"]), 0.1)


class PipelineDeriveTests(unittest.TestCase):
    def test_derive_workers_batch(self):
        s, p, c, o, phys = pp.derive_workers(10, register_workers=4)
        self.assertEqual(s, 1)
        self.assertEqual(phys, 1)
        self.assertGreaterEqual(p, 1)
        self.assertLessEqual(p, 4)
        self.assertGreaterEqual(c, 1)
        self.assertGreaterEqual(o, 1)

    def test_derive_workers_single(self):
        s, p, c, o, phys = pp.derive_workers(1, register_workers=1)
        self.assertEqual((p, c, o), (1, 1, 1))


if __name__ == "__main__":
    unittest.main()
