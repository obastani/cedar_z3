"""End-to-end implication regressions, including Cedar replay of witnesses."""

from copy import deepcopy
import json
import unittest
from unittest.mock import Mock, patch

import cedarpy
import z3

from cedar_z3 import (
    InvalidPolicy,
    SolverError,
    UnsupportedFeature,
    check_implication,
    is_at_least_as_conservative,
)


def record(**fields):
    return {"type": "Record", "attributes": fields}


def entity_type(name):
    return {"type": "Entity", "name": name}


def set_type(element):
    return {"type": "Set", "element": element}


STRING = {"type": "String"}
LONG = {"type": "Long"}
BOOLEAN = {"type": "Boolean"}


def schema():
    """Two actions share one typed request context, with optional data too."""
    context = record(
        x=LONG,
        flag=BOOLEAN,
        text=STRING,
        strings=set_type(STRING),
        other_strings=set_type(STRING),
        numbers=set_type(LONG),
        groups=set_type(entity_type("Group")),
        maybe={"type": "Boolean", "required": False},
        profile={
            "type": "Record",
            "required": False,
            "attributes": {
                "active": BOOLEAN,
                "nickname": {"type": "String", "required": False},
            },
        },
    )
    applies = {
        "principalTypes": ["User"],
        "resourceTypes": ["Doc"],
        "context": context,
    }
    return {
        "": {
            "entityTypes": {
                "User": {
                    "memberOfTypes": ["Group"],
                    "shape": record(
                        level=LONG,
                        role=STRING,
                        optional={"type": "Boolean", "required": False},
                        manager=entity_type("User"),
                    ),
                },
                "Group": {"memberOfTypes": ["Group", "Org"], "shape": record()},
                "Org": {"shape": record()},
                "Doc": {"shape": record(owner=entity_type("User"), label=STRING)},
            },
            "actions": {
                "read": {"appliesTo": deepcopy(applies)},
                "write": {"appliesTo": deepcopy(applies)},
            },
        }
    }


ALLOW = "permit(principal, action, resource);"
DENY = ""


def permit(condition):
    return f"permit(principal, action, resource) when {{ {condition} }};"


def forbid(condition):
    return f"forbid(principal, action, resource) when {{ {condition} }};"


class ImplicationTests(unittest.TestCase):
    def check(self, a, b, expected, *, input_schema=None, base=""):
        input_schema = schema() if input_schema is None else input_schema
        result = check_implication(a, b, input_schema, base_policies=base, timeout_ms=10_000)
        self.assertIs(result.holds, expected)
        self.assertIs(bool(result), expected)
        self.assertGreaterEqual(result.environments_checked, 1)
        if expected:
            self.assertIsNone(result.counterexample)
        else:
            self.assertIsNotNone(result.counterexample)
            witness = result.counterexample
            self.assertEqual((witness.decision_a, witness.decision_b), ("Allow", "Deny"))
            # Replay independently at the public Cedar API, including schema
            # validation of the concrete store produced from the SMT model.
            cs = cedarpy.Schema.from_json_str(json.dumps(input_schema))
            entities = cedarpy.Entities.from_json_str(json.dumps(witness.entities), schema=cs)
            aa = cedarpy.is_authorized(witness.request, base + "\n" + a, entities, schema=cs)
            bb = cedarpy.is_authorized(witness.request, base + "\n" + b, entities, schema=cs)
            self.assertEqual(aa.decision, cedarpy.Decision.Allow)
            self.assertEqual(bb.decision, cedarpy.Decision.Deny)
        return result

    def test_identity_and_boolean_api(self):
        source = permit("context.x >= 18")
        self.check(source, source, True)
        self.assertIs(is_at_least_as_conservative(source, ALLOW, schema()), True)
        self.assertIs(is_at_least_as_conservative(ALLOW, source, schema()), False)

    def test_direction_stricter_threshold_implies_looser(self):
        self.check(permit("context.x >= 21"), permit("context.x >= 18"), True)

    def test_reverse_direction_returns_counterexample(self):
        result = self.check(permit("context.x >= 18"), permit("context.x >= 21"), False)
        self.assertGreaterEqual(result.counterexample.request["context"]["x"], 18)
        self.assertLess(result.counterexample.request["context"]["x"], 21)

    def test_empty_policy_set_is_default_deny(self):
        self.check(DENY, ALLOW, True)
        self.check(ALLOW, DENY, False)
        self.check(DENY, DENY, True)

    def test_lone_forbids_are_decision_equivalent(self):
        self.check(forbid("context.x >= 18"), forbid("context.x >= 21"), True)
        self.check(forbid("context.x >= 21"), forbid("context.x >= 18"), True)

    def test_forbid_implication_with_shared_allow_baseline(self):
        self.check(forbid("context.x >= 18"), forbid("context.x >= 21"), True, base=ALLOW)
        self.check(forbid("context.x >= 21"), forbid("context.x >= 18"), False, base=ALLOW)

    def test_forbid_overrides_permit_regardless_of_policy_order(self):
        self.check(ALLOW + forbid("true"), DENY, True)
        self.check(forbid("true") + ALLOW, DENY, True)

    def test_multiple_permits_combine_by_or(self):
        self.check(permit("context.x < 0") + permit("context.x >= 0"), ALLOW, True)
        self.check(ALLOW, permit("context.x < 0") + permit("context.x >= 0"), True)

    def test_all_actions_are_examined(self):
        read_only = 'permit(principal, action == Action::"read", resource);'
        self.check(read_only, ALLOW, True)
        result = self.check(ALLOW, read_only, False)
        self.assertEqual(result.counterexample.request["action"]["id"], "write")

    def test_all_declared_principal_and_resource_types(self):
        s = schema()
        s[""]["entityTypes"]["Service"] = {"shape": record()}
        s[""]["entityTypes"]["Folder"] = {"shape": record()}
        for action in s[""]["actions"].values():
            action["appliesTo"]["principalTypes"].append("Service")
            action["appliesTo"]["resourceTypes"].append("Folder")
        self.check(ALLOW, 'permit(principal is User, action, resource);', False, input_schema=s)
        self.check(ALLOW, 'permit(principal, action, resource is Doc);', False, input_schema=s)

    def test_signed_long_overflow_changes_permission(self):
        increments = permit("context.x + 1 > context.x")
        self.check(increments, ALLOW, True)
        result = self.check(ALLOW, increments, False)
        self.assertEqual(result.counterexample.request["context"]["x"], 9223372036854775807)

    def test_error_negation_does_not_become_true(self):
        # The comparison is always true or an overflow error, so its negation
        # cannot authorize any request.
        self.check(permit("!(context.x + 1 > context.x)"), DENY, True)

    def test_unless_preserves_overflow_error(self):
        source = "permit(principal, action, resource) unless { context.x + 1 > context.x };"
        self.check(source, DENY, True)

    def test_erroring_forbid_is_skipped(self):
        broad_forbid = forbid("context.x + 1 > context.x")
        result = self.check(broad_forbid, forbid("true"), False, base=ALLOW)
        self.assertEqual(result.counterexample.request["context"]["x"], 9223372036854775807)

    def test_short_circuit_skips_erroneous_rhs(self):
        error = "context.x + 1 > context.x"
        self.check(ALLOW, permit(f"true || ({error})"), True)
        self.check(permit(f"false && ({error})"), DENY, True)
        self.check(ALLOW, permit(f"if false then ({error}) else true"), True)

    def test_optional_context_attribute_guard(self):
        guarded = "context has maybe && context.maybe"
        expanded = "if context has maybe then context.maybe else false"
        self.check(permit(guarded), permit(expanded), True)
        self.check(permit(expanded), permit(guarded), True)
        self.check(ALLOW, permit("context has maybe"), False)

    def test_nested_optional_record(self):
        active = "context has profile && context.profile.active"
        self.check(permit(active), permit("context has profile"), True)
        self.check(permit("context has profile"), permit(active), False)
        nickname = 'context has profile && context.profile has nickname && context.profile.nickname == "Ada"'
        self.check(permit(nickname), permit(active), False)

    def test_missing_entity_required_attribute_is_not_present(self):
        result = self.check(ALLOW, permit("principal has level"), False)
        principal = result.counterexample.request["principal"]
        self.assertNotIn(principal, [item["uid"] for item in result.counterexample.entities])

    def test_get_required_attribute_can_error_for_absent_entity(self):
        self.check(permit("principal.level == principal.level"), permit("principal has level"), True)
        self.check(permit("principal has level"), permit("principal.level == principal.level"), True)
        self.check(ALLOW, permit("principal.level == principal.level"), False)

    def test_aliasing_preserves_entity_attributes(self):
        a = permit("resource.owner == principal && resource.owner.level >= 21")
        b = permit("principal.level >= 18")
        self.check(a, b, True)

    def test_distinct_uids_do_not_share_attribute_values(self):
        a = permit("resource.owner != principal && resource.owner.level >= 21")
        b = permit("principal.level >= 18")
        self.check(a, b, False)

    def test_entity_type_and_id_jointly_determine_equality(self):
        self.check(permit('User::"same" == Group::"same"'), DENY, True)
        self.check(ALLOW, permit('User::"same" != Group::"same"'), True)

    def test_hierarchy_reflexive_even_for_absent_entity(self):
        self.check(ALLOW, permit("principal in principal"), True)
        self.check(permit('principal == User::"bob"'), permit('principal in User::"bob"'), True)

    def test_hierarchy_transitive(self):
        a = permit('principal in Group::"engineering" && Group::"engineering" in Org::"acme"')
        b = permit('principal in Org::"acme"')
        self.check(a, b, True)

    def test_hierarchy_not_symmetric(self):
        a = permit('Group::"child" in Group::"parent"')
        b = permit('Group::"parent" in Group::"child"')
        self.check(a, b, False)

    def test_hierarchy_acyclic(self):
        a = permit('Group::"a" in Group::"b" && Group::"b" in Group::"a"')
        self.check(a, DENY, True)

    def test_membership_requires_lhs_entity_but_not_parent_entity(self):
        a = permit('principal in Group::"missing"')
        self.check(a, permit("principal has level"), True)
        # A dangling ancestor reference is legal; accessing its attributes
        # need not succeed merely because the child belongs to it.
        s = schema()
        s[""]["entityTypes"]["Group"]["shape"] = record(label=STRING)
        self.check(a, permit('Group::"missing" has label'), False, input_schema=s)

    def test_action_hierarchy_is_fixed_by_schema(self):
        s = schema()
        s[""]["actions"]["all"] = {}
        for action in ("read", "write"):
            s[""]["actions"][action]["memberOf"] = [{"id": "all"}]
        self.check(ALLOW, 'permit(principal, action in Action::"all", resource);', True, input_schema=s)

    def test_action_typed_attributes_have_schema_declared_domain(self):
        s = schema()
        for action in s[""]["actions"].values():
            action["appliesTo"]["context"]["attributes"]["selected"] = entity_type("Action")
        complete = permit('context.selected == Action::"read" || context.selected == Action::"write"')
        self.check(ALLOW, complete, True, input_schema=s)
        self.check(ALLOW, permit('context.selected == Action::"read"'), False, input_schema=s)

    def test_action_typed_sets_have_schema_declared_domain(self):
        s = schema()
        for action in s[""]["actions"].values():
            action["appliesTo"]["context"]["attributes"]["selected"] = set_type(entity_type("Action"))
        complete = permit('[Action::"read", Action::"write"].containsAll(context.selected)')
        self.check(ALLOW, complete, True, input_schema=s)

    def test_default_entity_action_attribute_is_a_declared_action(self):
        s = schema()
        s[""]["entityTypes"]["User"]["shape"]["attributes"]["favorite"] = entity_type("Action")
        # Hierarchy membership makes the principal exist, but doesn't access
        # its attributes; the materializer supplies schema-valid defaults.
        self.check(permit('principal in Group::"g"'), DENY, False, input_schema=s)

    def test_in_literal_list_is_disjunction(self):
        a = permit('principal in [Group::"a", Group::"b"]')
        b = permit('principal in Group::"a" || principal in Group::"b"')
        self.check(a, b, True)
        self.check(b, a, True)

    def test_set_contains_all_implies_member(self):
        a = permit('context.strings.containsAll(["a", "b"])')
        b = permit('context.strings.contains("a")')
        self.check(a, b, True)
        self.check(b, a, False)

    def test_set_intersection_and_difference_witnesses(self):
        a = permit("context.strings.containsAny(context.other_strings)")
        b = permit("context.strings.containsAll(context.other_strings)")
        self.check(a, b, False)
        self.check(permit("context.strings != context.other_strings"), DENY, False)

    def test_set_empty_and_long_domain(self):
        self.check(permit("context.strings.isEmpty()"), permit('!context.strings.contains("a")'), True)
        self.check(permit('!context.strings.contains("a")'), permit("context.strings.isEmpty()"), False)
        self.check(permit("context.numbers.contains(context.x)"), permit("!context.numbers.isEmpty()"), True)
        self.check(permit("!context.numbers.isEmpty()"), permit("context.numbers.contains(0)"), False)

    def test_record_equality_ignores_field_order(self):
        self.check(ALLOW, permit("{x: context.x, flag: context.flag} == {flag: context.flag, x: context.x}"), True)

    def test_unicode_and_literal_escape_strings(self):
        source = permit('context.text == "🐱"')
        result = self.check(source, permit('context.text == "cat"'), False)
        self.assertEqual(result.counterexample.request["context"]["text"], "🐱")
        self.check(permit(r'context.text == "\\u{61}"'), permit('context.text == "a"'), False)

    def test_syntax_errors_and_validation_errors_raise(self):
        with self.assertRaises(InvalidPolicy):
            check_implication("not a Cedar policy", ALLOW, schema())
        with self.assertRaises(InvalidPolicy):
            check_implication(permit("context.unknown"), ALLOW, schema())

    def test_unsupported_pattern_operator_raises(self):
        with self.assertRaises(UnsupportedFeature):
            check_implication(permit('context.text like "a*"'), ALLOW, schema())

    def test_unsupported_symbolic_hierarchy_set_raises(self):
        with self.assertRaises(UnsupportedFeature):
            check_implication(permit("principal in context.groups"), ALLOW, schema())

    def test_solver_unknown_is_never_reported_as_a_boolean(self):
        solver = Mock()
        solver.check.return_value = z3.unknown
        solver.reason_unknown.return_value = "test timeout"
        with patch("cedar_z3.checker.z3.Solver", return_value=solver):
            with self.assertRaisesRegex(SolverError, "test timeout"):
                check_implication(ALLOW, ALLOW, schema(), timeout_ms=1)

    def test_invalid_timeout_is_rejected(self):
        for value in (0, -1, True, 1.5):
            with self.subTest(timeout=value), self.assertRaises(ValueError):
                check_implication(ALLOW, ALLOW, schema(), timeout_ms=value)


if __name__ == "__main__":
    unittest.main()
