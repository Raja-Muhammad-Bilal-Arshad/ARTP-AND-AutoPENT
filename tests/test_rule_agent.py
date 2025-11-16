import os
import sys
import json
import copy
import pytest

# ensure repo root is on PYTHONPATH for tests when run locally
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from agents.rule_based.pipeline import RuleAgent, RuleAgentConfig


@pytest.fixture()
def sample_state():
    return {
        "hosts": [{"ip": "10.0.0.2"}, {"ip": "10.0.0.3"}],
        "services": {
            "10.0.0.2": [{"name": "http", "port": 80, "version": "1.0"}, {"name": "ssh", "port": 22}],
            "10.0.0.3": [{"name": "minio", "port": 9000, "version": "2020.1"}]
        },
        "web_endpoints": [
            {"host": "10.0.0.2", "path": "/login"},
            {"host": "10.0.0.3", "path": "/data/backup"}
        ],
        "accounts": {
            "10.0.0.3": [{"service": "minio", "username": "admin", "password": "admin", "from_check_creds": True}]
        },
        "telemetry_confidence": 0.9,
    }


def test_propose_plan_structure(sample_state):
    cfg = {"seed": 123, "max_actions": 200, "verbosity": 0}
    agent = RuleAgent(cfg)
    plan = agent.propose_plan(sample_state)
    assert isinstance(plan, list), "plan must be a list"
    assert len(plan) > 0, "plan should contain at least one step"
    for step in plan:
        assert isinstance(step, dict)
        assert "action" in step
        assert "target" in step
        assert "confidence" in step
        assert "rationale" in step


def test_determinism_with_seed(sample_state):
    cfg_a = {"seed": 999, "max_actions": 200}
    cfg_b = {"seed": 999, "max_actions": 200}
    a = RuleAgent(cfg_a)
    b = RuleAgent(cfg_b)
    plan_a = a.propose_plan(sample_state)
    plan_b = b.propose_plan(sample_state)
    assert plan_a == plan_b, "Agents with same seed must produce identical plans"


def test_max_actions_trimming(sample_state):
    cfg = {"seed": 42, "max_actions": 3}
    agent = RuleAgent(cfg)
    plan = agent.propose_plan(sample_state)
    assert len(plan) <= 3


def test_normalize_state_variants():
    # services as list-of-dicts (alternate shape)
    state_list = {
        "hosts": [{"ip": "10.0.0.2"}],
        "services": [
            {"host": "10.0.0.2", "name": "http", "port": 80}
        ],
        "web_endpoints": [],
    }
    cfg = {"seed": 1, "max_actions": 50}
    agent = RuleAgent(cfg)
    plan_list = agent.propose_plan(state_list)

    # services as dict-of-lists (canonical shape)
    state_map = copy.deepcopy(state_list)
    state_map["services"] = {"10.0.0.2": [{"name": "http", "port": 80}]}
    plan_map = agent.propose_plan(state_map)

    assert isinstance(plan_list, list)
    assert isinstance(plan_map, list)
    assert len(plan_list) >= 1
    assert len(plan_map) >= 1
