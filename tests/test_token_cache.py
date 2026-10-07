import sys
from unittest import mock

import pytest

from mfiles_grpc import token_cache
from mfiles_grpc.token_cache import KeyringCache, TokenCacheError


class PasswordDeleteError(Exception):
    """Same name as the keyring package's: that is how "nothing there" is told from a failure."""


class FakeKeyring:
    """The three keyring calls the cache makes, over a dict."""

    def __init__(self):
        self.stored = {}

    def get_password(self, service, name):
        return self.stored.get((service, name))

    def set_password(self, service, name, password):
        self.stored[(service, name)] = password

    def delete_password(self, service, name):
        if (service, name) not in self.stored:
            raise PasswordDeleteError("not found")
        del self.stored[(service, name)]


def cache(fake=None) -> KeyringCache:
    return KeyringCache("vault.example|AAAA", fake or FakeKeyring())


def test_entry_name_is_the_same_for_every_spelling_of_the_account():
    assert token_cache.entry_name("Vault.Example", "{aaaa-bbbb}") == "vault.example|AAAA-BBBB"
    assert token_cache.entry_name("vault.example", "AAAA-BBBB") == "vault.example|AAAA-BBBB"


def test_nothing_remembered_loads_as_none():
    assert cache().load() is None


def test_a_saved_refresh_token_is_loaded_and_replaced_by_the_next_one():
    fake = FakeKeyring()
    c = cache(fake)
    c.save("refresh-1")
    assert c.load() == "refresh-1"
    c.save("refresh-2")
    assert c.load() == "refresh-2"
    assert fake.stored == {("mfiles-grpc", "vault.example|AAAA"): "refresh-2"}


def test_clear_forgets_the_token_and_forgetting_nothing_is_fine():
    c = cache()
    c.save("refresh-1")
    c.clear()
    assert c.load() is None
    c.clear()


def test_a_store_failure_is_reported_without_the_stores_own_message():
    # The message could carry the secret; the type name is enough to tell what went wrong.
    broken = mock.Mock()
    broken.get_password.side_effect = RuntimeError("secret-refresh-token")
    broken.set_password.side_effect = RuntimeError("secret-refresh-token")
    broken.delete_password.side_effect = RuntimeError("secret-refresh-token")
    c = cache(broken)
    for call in (c.load, lambda: c.save("x"), c.clear):
        with pytest.raises(TokenCacheError) as e:
            call()
        assert "secret-refresh-token" not in str(e.value)
        assert "RuntimeError" in str(e.value)


def test_without_the_keyring_package_the_error_says_how_to_get_it():
    with mock.patch.dict(sys.modules, {"keyring": None}):
        with pytest.raises(TokenCacheError, match=r"mfiles-grpc\[keyring\]"):
            KeyringCache("vault.example|AAAA").load()


def test_repr_names_the_entry_and_nothing_else():
    assert repr(cache()) == "KeyringCache(entry='vault.example|AAAA')"


def test_open_cache_without_a_kind_remembers_nothing():
    assert token_cache.open_cache(None, "vault.example", "{AAAA}") is None


def test_open_cache_keyring_names_the_account():
    c = token_cache.open_cache("keyring", "Vault.Example", "{aaaa}")
    assert isinstance(c, KeyringCache)
    assert c.entry == "vault.example|AAAA"


def test_open_cache_with_an_unknown_kind_is_an_error():
    with pytest.raises(ValueError, match="file"):
        token_cache.open_cache("file", "vault.example", "{AAAA}")
