"""Regression tests for the last review items: key-inactive framing, nonce-full alert, surrogates."""
import pytest

from t4.detect import export
from t4.node import freshness
from t4.node.common import NodeError, check_text


def test_replayed_old_key_is_not_attributed_to_the_signer():
    assert "NODE-KEY-INACTIVE" in export.NOT_FROM_SIGNER_RULES


def test_nonce_store_full_raises_an_alert():
    assert "NODE-NONCE-STORE-FULL" in freshness.ALERT_TEXT


@pytest.mark.parametrize("bad", ["a\ud800b", "\udfff"])
def test_lone_surrogates_are_refused(bad):
    with pytest.raises(NodeError):
        check_text(bad)


def test_ordinary_unicode_is_still_accepted():
    assert check_text("Zoë-名前") == "Zoë-名前"
