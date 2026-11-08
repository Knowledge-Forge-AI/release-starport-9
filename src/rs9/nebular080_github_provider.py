"""Production 0.8 read-only GitHub API provider boundary."""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from typing import Any

from rs9.errors import ContractError
from rs9.github import PublicClient


def github_public_client(
    *,
    environ: Mapping[str, str] | None = None,
    client: PublicClient | None = None,
) -> PublicClient:
    """Build the closed public client used by hosted 0.8 read paths.

    A caller may supply an already constructed PublicClient for offline tests;
    production construction is limited to the GitHub Actions token boundary.
    No caller-supplied headers, URL, or credential are accepted here.
    """
    env = os.environ if environ is None else environ
    if client is None:
        if env.get("GITHUB_ACTIONS", "").strip().lower() != "true":
            raise ContractError("GITHUB_PROVIDER_UNAVAILABLE", "Hosted GitHub API provider is required")
        token = env.get("RS9_GITHUB_READ_TOKEN", "").strip()
        if not token:
            raise ContractError("GITHUB_PROVIDER_CREDENTIALS", "Hosted GitHub API credential is required")
        client = PublicClient(api_token=token)
    if not isinstance(client, PublicClient):
        raise ContractError("GITHUB_PROVIDER_INVALID", "Bounded GitHub API client is required")
    return client


def github_json_provider(
    *,
    environ: Mapping[str, str] | None = None,
    client: PublicClient | None = None,
) -> Callable[[str], Any]:
    """Build the closed GitHub JSON reader used by the hosted 0.8 route.

    The client construction and the callable adapter share one credential and
    request-class boundary, so acquisition and history cannot choose separate
    or caller-supplied public transports.
    """
    client = github_public_client(environ=environ, client=client)

    def get(url: str) -> Any:
        try:
            return client.json(url, request_class="github-api", no_redirect=True)
        except ContractError:
            raise
        except Exception:
            raise ContractError("GITHUB_PROVIDER_FAILED", "Bounded GitHub API request failed") from None

    return get
