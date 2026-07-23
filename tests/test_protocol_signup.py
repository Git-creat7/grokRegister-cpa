# -*- coding: utf-8 -*-
import unittest

import protocol_signup as ps


class ProtocolSignupHelpers(unittest.TestCase):
    def test_build_signup_body_shape(self):
        raw = ps.build_signup_body("a@b.com", "pass", "123456", "cf-token")
        data = __import__("json").loads(raw.decode("utf-8"))
        self.assertEqual(len(data), 2)
        self.assertEqual(data[0]["emailValidationCode"], "123456")
        self.assertEqual(data[0]["createUserAndSessionRequest"]["email"], "a@b.com")
        self.assertEqual(data[0]["turnstileToken"], "cf-token")
        self.assertEqual(data[1]["client"], "$T")

    def test_is_session_sso_rejects_hop_config(self):
        # minimal fake JWT with config.success_url
        import base64
        import json

        def make(payload):
            h = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=")
            p = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
            return f"{h}.{p}.sig"

        hop = make({"config": {"success_url": "https://auth.grokusercontent.com/set-cookie"}})
        self.assertFalse(ps.is_session_sso(hop))
        good = make({"sub": "user-1", "sid": "abc"})
        # pad length
        self.assertTrue(ps.is_session_sso(good + "x" * 20) or ps.is_session_sso(good))

    def test_grpc_frame_roundtrip_length(self):
        inner = ps._pb_str(1, "user@example.com")
        frame = ps._grpc_web_frame(inner)
        self.assertEqual(frame[0], 0)
        length = int.from_bytes(frame[1:5], "big")
        self.assertEqual(length, len(inner))
        self.assertEqual(frame[5:], inner)


if __name__ == "__main__":
    unittest.main()
