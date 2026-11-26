"""TEST DOUBLES ONLY.

``InsecureTestSigner`` gives NO security: its "public" key is the secret. It
exists so protocol logic can be tested without the real ML-DSA wrapper. It must
never be imported by product code. Tests against the real modules are in
``test_real_modules.py``.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets


class InsecureTestSigner:
    def sig_keygen(self) -> tuple[bytes, bytes]:
        key = secrets.token_bytes(32)
        return key, key

    def sign(self, sk: bytes, msg: bytes) -> bytes:
        return hmac.new(sk, msg, hashlib.sha256).digest()

    def verify(self, pk: bytes, msg: bytes, sig: bytes) -> bool:
        return hmac.compare_digest(self.sign(pk, msg), sig)


class MemoryLog:
    """Records appends. It has no hash chain."""

    def __init__(self, *_: object) -> None:
        self.entries: list[dict] = []
        self.fail = False

    def append(self, **entry: object) -> dict:
        if self.fail:
            raise OSError("log unavailable")
        for value in entry["detail"].values():
            assert type(value) in (str, int, bool), "detail values must be str, int or bool"
        self.entries.append({"seq": len(self.entries) + 1, **entry})
        return {"seq": len(self.entries), "hash": ""}

    def alert(self, *, rule, explanation, actor="", target="", request_id="", entries=(),
              request_ids=(), detail=None) -> dict:
        extra = {**(detail or {}), "explanation": explanation,
                 "entries": json.dumps(list(entries)),
                 "request_ids": json.dumps(list(request_ids))}
        return self.append(actor=actor, action="alert", target=target, decision="alert",
                           rule=rule, request_id=request_id, detail=extra)

    def rules(self) -> list[str]:
        return [entry["rule"] for entry in self.entries]
