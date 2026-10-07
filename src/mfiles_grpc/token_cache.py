# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

"""
Remembering a browser sign-in between runs, so that MFA is asked once and not on every run.

What is remembered is the OAuth refresh token and nothing else. The access token is short-lived,
and a JWT does not fit where this is kept anyway: Windows Credential Manager takes at most 2560 bytes
per entry, and the keyring package stores text as UTF-16. Each run therefore trades the refresh
token for a fresh access token with one call to the token endpoint, without a browser.

A refresh token is a credential: whoever holds it can sign in as the user, to this vault, without
MFA, until the IdP expires or revokes it. It is kept in the operating system's credential store
through the keyring package, never in a file, and never in a log line or a repr. Remembering is
opt-in: set token-cache = "keyring" in [m-files.tool.grpc], and install the extra:

    pip install "mfiles-grpc[keyring]"

`mfiles-grpc forget-token` removes the remembered sign-in.
"""

import logging
from typing import Optional, Protocol

log = logging.getLogger(__name__)

KEYRING_SERVICE = "mfiles-grpc"

# The values token-cache accepts in the settings file.
CACHE_KINDS = ("keyring",)


class TokenCacheError(Exception):
    """The credential store could not be read or written."""


class TokenCache(Protocol):
    """Where one account's refresh token is kept."""

    def load(self) -> Optional[str]:
        """:return: The remembered refresh token, or None when there is none"""

    def save(self, refresh_token: str) -> None:
        """:param refresh_token: The token to remember, replacing any earlier one"""

    def clear(self) -> None:
        """Forget the refresh token. Nothing remembered is not an error."""


def entry_name(host: str, vault: str) -> str:
    """
    :param host: The vault host
    :param vault: The vault GUID, in any case and with or without braces
    :return: The name one account's token is kept under. One sign-in serves one vault on one host.
    """
    return f"{host.lower()}|{vault.strip().strip('{}').upper()}"


class KeyringCache:
    """The refresh token of one account, kept in the operating system's credential store."""

    def __init__(self, entry: str, keyring_module=None):
        """
        :param entry: See entry_name()
        :param keyring_module: The keyring package, or a stand-in for it in tests
        """
        self.entry = entry
        self._keyring = keyring_module

    def _backend(self):
        if self._keyring is None:
            try:
                import keyring
            except ImportError as e:
                raise TokenCacheError(
                    'token-cache = "keyring" needs the keyring package: pip install "mfiles-grpc[keyring]"') from e
            self._keyring = keyring
        return self._keyring

    def load(self) -> Optional[str]:
        try:
            return self._backend().get_password(KEYRING_SERVICE, self.entry) or None
        except TokenCacheError:
            raise
        except Exception as e:
            raise TokenCacheError(f"Cannot read the credential store: {type(e).__name__}") from e

    def save(self, refresh_token: str) -> None:
        try:
            self._backend().set_password(KEYRING_SERVICE, self.entry, refresh_token)
        except TokenCacheError:
            raise
        except Exception as e:
            raise TokenCacheError(f"Cannot write the credential store: {type(e).__name__}") from e

    def clear(self) -> None:
        backend = self._backend()
        try:
            backend.delete_password(KEYRING_SERVICE, self.entry)
        except Exception as e:
            # Nothing remembered is what was asked for. Telling "not there" from "cannot reach the
            # store" is the keyring package's PasswordDeleteError against everything else.
            if type(e).__name__ != "PasswordDeleteError":
                raise TokenCacheError(f"Cannot clear the credential store: {type(e).__name__}") from e

    def __repr__(self) -> str:
        return f"KeyringCache(entry={self.entry!r})"


def open_cache(kind: Optional[str], host: str, vault: str) -> Optional[TokenCache]:
    """
    :param kind: The token-cache setting: one of CACHE_KINDS, or None for no remembering
    :param host: The vault host
    :param vault: The vault GUID
    :return: The cache to use, or None when sign-in is not remembered
    """
    if kind is None:
        return None
    if kind == "keyring":
        return KeyringCache(entry_name(host, vault))
    raise ValueError(f"token-cache = {kind!r}: expected one of {', '.join(CACHE_KINDS)}")
