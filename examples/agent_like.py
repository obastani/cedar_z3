"""Compare agent permissions, including Cedar's ``like`` operator.

From the project directory:

    python -m pip install .
    python examples/agent_like.py

SCHEMA is the JSON equivalent of the accompanying agent.cedarschema file.
The checker accepts the dictionary directly, so no schema-conversion tool is
needed. Cedar ``like`` matches the entire string; ``*`` can match zero or more
characters, including slashes. The path checks below use that string matching
semantics; they do not normalize filesystem paths.
"""
from dataclasses import asdict
import json

from cedar_z3 import check_implication


SCHEMA = {
    "": {
        "entityTypes": {
            "Agent": {},
            "File": {
                "shape": {"type": "Record", "attributes": {"path": {"type": "String"}}},
            },
            "Url": {
                "shape": {"type": "Record", "attributes": {"host": {"type": "String"}}},
            },
            "Port": {
                "shape": {"type": "Record", "attributes": {"port": {"type": "Long"}}},
            },
            "Package": {
                "shape": {
                    "type": "Record",
                    "attributes": {
                        "installer": {"type": "String"},
                        "name": {"type": "String"},
                    },
                },
            },
        },
        "actions": {
            "ReadExecute": {
                "appliesTo": {"principalTypes": ["Agent"], "resourceTypes": ["File"]},
            },
            "Write": {
                "appliesTo": {"principalTypes": ["Agent"], "resourceTypes": ["File"]},
            },
            "FetchUrl": {
                "appliesTo": {"principalTypes": ["Agent"], "resourceTypes": ["Url"]},
            },
            "ListenPort": {
                "appliesTo": {"principalTypes": ["Agent"], "resourceTypes": ["Port"]},
            },
            "InstallPackage": {
                "appliesTo": {"principalTypes": ["Agent"], "resourceTypes": ["Package"]},
            },
        },
    },
}


# A grants a narrower set of requests for each of the five actions.
A = '''
permit(principal is Agent, action == Action::"ReadExecute", resource is File)
when { resource.path like "/workspace/app/*" };

permit(principal is Agent, action == Action::"Write", resource is File)
when { resource.path like "/workspace/output/*.json" };

permit(principal is Agent, action == Action::"FetchUrl", resource is Url)
when { resource.host == "api.example.com" };

permit(principal is Agent, action == Action::"ListenPort", resource is Port)
when { resource.port >= 8000 && resource.port <= 8100 };

permit(principal is Agent, action == Action::"InstallPackage", resource is Package)
when {
    resource.installer == "pip"
    && ["requests", "pytest"].contains(resource.name)
};
'''


# B broadens file paths, hostnames, the port range, and the package allowlist.
B = '''
permit(principal is Agent, action == Action::"ReadExecute", resource is File)
when { resource.path like "/workspace/*" };

permit(principal is Agent, action == Action::"Write", resource is File)
when { resource.path like "/workspace/*" };

permit(principal is Agent, action == Action::"FetchUrl", resource is Url)
when { resource.host like "*.example.com" };

permit(principal is Agent, action == Action::"ListenPort", resource is Port)
when { resource.port >= 1024 && resource.port <= 65535 };

permit(principal is Agent, action == Action::"InstallPackage", resource is Package)
when {
    resource.installer == "pip"
    && ["requests", "pytest", "numpy", "pandas"].contains(resource.name)
};
'''


def main() -> None:
    forward = check_implication(A, B, SCHEMA)
    assert forward.holds is True
    assert forward.environments_checked == 5
    print("A is at least as conservative as B:", forward.holds)
    print("Request environments checked:", forward.environments_checked)

    reverse = check_implication(B, A, SCHEMA)
    assert reverse.holds is False
    assert reverse.counterexample is not None
    print("B is at least as conservative as A:", reverse.holds)
    print("Counterexample to B => A (allowed by B, denied by A):")
    # The result labels refer to this call's arguments: decision_a describes
    # B, and decision_b describes A. The checker has already replayed both
    # decisions with Cedar before returning this concrete request and store.
    print(json.dumps(asdict(reverse.counterexample), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
