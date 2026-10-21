"""Differential checks of expression outcomes and errors against Cedar itself."""

import unittest

import cedarpy
import z3

from cedar_z3.expressions import ExpressionCompiler
from cedar_z3.model import (
    BOOL, LONG, LONG_MAX, LONG_MIN, Field, Type, Value, element_sort, set_member,
)


class ConcreteEnvironment:
    """Concrete inputs isolate expression semantics from symbolic entity setup."""

    def __init__(self, integer, flag, present):
        self.variables = {
            "context": Value(
                Type("record"),
                {
                    "x": Field(z3.BoolVal(True), Value(LONG, z3.IntVal(integer))),
                    "b": Field(z3.BoolVal(present), Value(BOOL, z3.BoolVal(flag))),
                },
            )
        }

    def observe(self, value):
        pass

    def get_attr(self, base, name):
        field = base.data[name]
        return Value(
            field.value.type,
            field.value.data,
            z3.And(base.ok, field.present, field.value.ok),
        )

    def has_attr(self, base, names):
        if len(names) != 1:
            raise AssertionError("These tests use single-attribute access")
        return Value(BOOL, base.data[names[0]].present, base.ok)

    def make_set(self, members):
        element_type = members[0].type
        result = z3.EmptySet(element_sort(element_type))
        for member in members:
            result = z3.SetAdd(result, set_member(member))
        return Value(
            Type("set", element=element_type),
            result,
            z3.And(*(member.ok for member in members)),
        )


class ExpressionDifferentialTests(unittest.TestCase):
    def test_matches_cedar_truth_and_errors_at_integer_boundaries(self):
        expressions = [
            "context.x + 1 > context.x",
            "-context.x == context.x",
            "!(context.x + 1 > context.x)",
            "context has b && context.b",
            "!(context has b && context.b)",
            "context has b || context.b",
            "if context has b then context.b else true",
            "[context.x, 4].contains(4)",
            "[].containsAll([])",
            "[].containsAll([context.x])",
            "[context.x].containsAny([])",
            "[context.x].containsAny([4])",
            "[context.x].isEmpty()",
            "(if context.x == 4 then [] else [context.x]).isEmpty()",
            "{a: context.x, b: true} == {b: true, a: context.x}",
        ]
        # 15 expressions x 5 integer cases x 3 optional-field cases = 225
        # independent comparisons with the actual Cedar evaluator.
        for expression in expressions:
            source = f"permit(principal, action, resource) when {{ {expression} }};"
            policies = cedarpy.PolicySet.from_str(source)
            node = policies.to_pst().static_policies["policy0"].clauses[0].expr
            for integer in (LONG_MIN, -1, 0, 4, LONG_MAX):
                for flag, present in ((False, False), (False, True), (True, True)):
                    with self.subTest(expression=expression, integer=integer, flag=flag, present=present):
                        context = {"x": integer}
                        if present:
                            context["b"] = flag
                        request = {
                            "principal": {"type": "User", "id": "u"},
                            "action": {"type": "Action", "id": "a"},
                            "resource": {"type": "R", "id": "r"},
                            "context": context,
                        }
                        actual = cedarpy.is_authorized(request, policies, [])
                        encoded = ExpressionCompiler(
                            ConcreteEnvironment(integer, flag, present)
                        ).compile(node)
                        # Array/set equalities need a solver even when their
                        # inputs are concrete; simplify() is not a decision
                        # procedure. Ask for either kind of disagreement.
                        solver = z3.Solver()
                        solver.set(timeout=2_000)
                        solver.add(z3.Or(
                            z3.And(encoded.ok, encoded.data) != z3.BoolVal(actual.allowed),
                            encoded.ok != z3.BoolVal(not bool(actual.diagnostics.errors)),
                        ))
                        self.assertEqual(solver.check(), z3.unsat)


if __name__ == "__main__":
    unittest.main()
