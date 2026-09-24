# agmi: Agent Memory Integrity test suite
# Copyright (c) 2026 Yasha Khandelwal <yasha.khandelwal@tech4biz.io>
# SPDX-License-Identifier: MIT

"""The memory agent: it finds and proves landings on a weak store, finds
fewer and has to work harder on the defended one, and refuses a network
target without authorisation."""


import pytest

from agmi.adapters.defended_memory import DefendedMemoryAdapter
from agmi.adapters.naive_memory import NaiveMemoryAdapter
from agmi.agent import hunt
from agmi.agent.authz import (NotAuthorised, authorise_library, authorise_url,
                              CONSENT_FILE_ENV)
from agmi.agent.report import to_text, to_json


def test_hunt_lands_every_attack_on_the_naive_store():
    r = hunt(NaiveMemoryAdapter(), mutate=True)
    found = {f.attack for f in r.findings}
    assert found == {"memory_injection", "retrieval_hijack",
                     "indirect_prompt_injection", "update_poisoning",
                     "metadata_poisoning"}
    # cross_session_bleed is not a landing (it needs no attacker write); the
    # naive store scopes by user, so it is correctly not reported.
    for f in r.findings:
        assert f.repro and f.repro[-1].startswith("retrieve(")


def test_hunt_works_harder_on_the_defended_store():
    weak = hunt(NaiveMemoryAdapter(), mutate=True)
    strong = hunt(DefendedMemoryAdapter(), mutate=True)
    assert strong.tried > weak.tried          # it had to search more
    assert len(strong.findings) < len(weak.findings)
    # the landings it does find are all on the signed channel, the honest
    # limit: a signed write is a genuine write as far as a store can tell.
    for f in strong.findings:
        assert f.channel == "agent-laundered", f.attack


def test_each_finding_is_reproducible_and_proven():
    r = hunt(NaiveMemoryAdapter(), mutate=True)
    for f in r.findings:
        assert f.key and f.query
        assert any("add_memory" in s for s in f.repro)
        assert f"contains {f.key!r}" in f.repro[-1]


def test_a_clean_store_yields_no_findings():
    # a store that keeps everything out (silent read path) should land
    # nothing; the hunt reports honestly rather than inventing a finding.
    class Clean(NaiveMemoryAdapter):
        def retrieve(self, query, user_id, k=5):
            return []

        def retrieve_where(self, query, user_id, where, k=5):
            return []

    r = hunt(Clean(), mutate=True)
    assert r.findings == []
    assert "No landing found" in to_text(r)


def test_report_json_round_trips():
    import json
    r = hunt(NaiveMemoryAdapter(), mutate=False)
    data = json.loads(to_json(r))
    assert data["findings"] and data["authorisation"].startswith("library")


def test_authorise_library_is_always_allowed():
    a = authorise_library()
    assert a.kind == "library"


def test_a_url_is_refused_without_authorisation(monkeypatch):
    monkeypatch.delenv(CONSENT_FILE_ENV, raising=False)
    with pytest.raises(NotAuthorised):
        authorise_url("https://someone-elses-server.example/memory")


def test_localhost_is_allowed():
    assert authorise_url("http://127.0.0.1:8080/mcp").kind == "localhost"


def test_a_url_is_allowed_with_an_env_token(monkeypatch):
    monkeypatch.setenv("AGMI_TARGET_TOKEN_MY_HOST_EXAMPLE", "yes")
    a = authorise_url("https://my-host.example/memory")
    assert a.kind == "env-token"


def test_a_url_is_allowed_with_a_consent_file(tmp_path, monkeypatch):
    f = tmp_path / "consent.txt"
    f.write_text("# hosts I control\nmy-host.example\n")
    monkeypatch.setenv(CONSENT_FILE_ENV, str(f))
    a = authorise_url("https://my-host.example/memory")
    assert a.kind == "consent-file"
