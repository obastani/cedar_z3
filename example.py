"""Run with: python example.py"""
from dataclasses import asdict
import json

from cedar_z3 import check_implication, is_at_least_as_conservative


SCHEMA = {
    "": {
        "entityTypes": {"User": {}, "Document": {}},
        "actions": {
            "read": {
                "appliesTo": {
                    "principalTypes": ["User"],
                    "resourceTypes": ["Document"],
                    "context": {
                        "type": "Record",
                        "attributes": {"clearance": {"type": "Long"}},
                    },
                },
            },
        },
    },
}

A = '''
permit(principal, action == Action::"read", resource)
when { context.clearance >= 5 };
'''

B = '''
permit(principal, action == Action::"read", resource)
when { context.clearance >= 3 };
'''

if __name__ == "__main__":
    print("A is at least as conservative as B:",
          is_at_least_as_conservative(A, B, SCHEMA))
    reverse = check_implication(B, A, SCHEMA)
    print("B is at least as conservative as A:", reverse.holds)
    print("Counterexample to the reverse implication:")
    print(json.dumps(asdict(reverse.counterexample), indent=2, ensure_ascii=False))
