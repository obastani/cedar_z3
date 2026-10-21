"""Public policy implication API. Runtime dependencies: cedarpy, z3-solver."""
from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any

import cedarpy
from cedarpy import pst
import z3

from .counterexample import Materializer
from .environment import Environment
from .expressions import ExpressionCompiler
from .model import (
    BOOL, CounterexampleError, InvalidPolicy, SolverError, UnsupportedFeature,
    eq_values, string_literal,
)
from .schema import SchemaModel


@dataclass(frozen=True)
class Counterexample:
    request: dict[str, Any]
    entities: list[dict[str, Any]]
    decision_a: str = "Allow"
    decision_b: str = "Deny"


@dataclass(frozen=True)
class ImplicationResult:
    holds: bool
    counterexample: Counterexample | None
    environments_checked: int

    def __bool__(self):
        return self.holds


def _scope(scope, variable, env):
    def entity(uid):
        if isinstance(uid, pst.Slot):
            raise UnsupportedFeature("Bind template slots before checking implication")
        return env.entity(str(uid.type), string_literal(uid.id))

    if isinstance(scope, pst.ScopeAny):
        return z3.BoolVal(True)
    if isinstance(scope, (pst.ScopeEq, pst.ActionEq)):
        return eq_values(variable, entity(scope.entity)).data
    if isinstance(scope, pst.ScopeIn):
        return env.in_entity(variable, entity(scope.entity)).data
    if isinstance(scope, pst.ActionIn):
        return z3.Or(*[env.in_entity(variable, entity(uid)).data for uid in scope.entities])
    if isinstance(scope, (pst.ScopeIs, pst.ScopeIsIn)):
        same_type = variable.type.name == str(scope.entity_type)
        if not same_type or isinstance(scope, pst.ScopeIs):
            return z3.BoolVal(same_type)
        return env.in_entity(variable, entity(scope.entity)).data
    raise UnsupportedFeature(f"Unsupported scope: {type(scope).__name__}")


def _allow(policy_set, env):
    permits, forbids = [], []
    compiler = ExpressionCompiler(env)
    for policy in policy_set.static_policies.values():
        matches = z3.simplify(z3.And(*[
            _scope(getattr(policy, name), env.variables[name], env)
            for name in ("principal", "action", "resource")
        ]))
        for clause in policy.clauses:
            if z3.is_false(matches):
                break
            condition = compiler.compile(clause.expr)
            if condition.type != BOOL:
                raise UnsupportedFeature("A Cedar policy condition must be Boolean")
            if isinstance(clause, pst.When):
                value = condition.data
            elif isinstance(clause, pst.Unless):
                value = z3.Not(condition.data)
            else:
                raise UnsupportedFeature(f"Unknown clause {type(clause).__name__}")
            # A policy contributes only if every evaluated condition succeeds
            # and is satisfied. Errors do not contribute a permit OR a forbid.
            matches = z3.simplify(z3.And(matches, condition.ok, value))
        if policy.effect == "permit":
            permits.append(matches)
        elif policy.effect == "forbid":
            forbids.append(matches)
        else:
            raise UnsupportedFeature(f"Unknown policy effect {policy.effect}")
    return z3.And(z3.Or(*permits), z3.Not(z3.Or(*forbids)))


def check_implication(
    policy_a: str,
    policy_b: str,
    schema: dict[str, Any],
    *,
    base_policies: str = "",
    timeout_ms: int | None = None,
) -> ImplicationResult:
    """Check whether A is at least as conservative as B.

    Returns ``holds=True`` iff no schema-conforming request/entity store can
    be allowed by ``base_policies + A`` and denied by ``base_policies + B``.
    A string may contain one policy, multiple policies, or an empty policy set.
    All schema-declared (principal type, action, resource type) combinations
    are considered. Entity IDs, context values and entity stores are symbolic,
    not restricted to a supplied sample or a user-chosen size bound.

    If the implication fails, the result contains a finite counterexample
    replayed with cedarpy. Unsupported syntax, invalid inputs, solver errors,
    and failed model decoding raise exceptions; they never produce True.
    The optional timeout applies to each Z3 query; the default has no timeout.

    This is decision implication. It does not compare diagnostics or policy
    match sets. In particular a policy set with only forbids always denies.
    """
    if not all(isinstance(text, str) for text in (policy_a, policy_b, base_policies)):
        raise TypeError("Policies must be Cedar source strings")
    if not isinstance(schema, dict):
        raise TypeError("schema must be a Cedar JSON-schema dictionary")
    if timeout_ms is not None and (type(timeout_ms) is not int or timeout_ms <= 0):
        raise ValueError("timeout_ms must be a positive integer or None")

    source_a, source_b = base_policies + "\n" + policy_a, base_policies + "\n" + policy_b
    try:
        cedar_schema = cedarpy.Schema.from_json_str(json.dumps(schema))
        parsed_a = cedarpy.PolicySet.from_str(source_a)
        parsed_b = cedarpy.PolicySet.from_str(source_b)
        trees = (parsed_a.to_pst(), parsed_b.to_pst())
    except (ValueError, TypeError) as error:
        raise InvalidPolicy(str(error)) from error
    for label, source, tree in zip(("A", "B"), (source_a, source_b), trees):
        if tree.templates or tree.template_links:
            raise UnsupportedFeature(f"Policy set {label} contains templates; supply static policies")
        validation = cedarpy.validate_policies(source, cedar_schema)
        if not validation.validation_passed:
            raise InvalidPolicy(f"Policy set {label} does not validate: {validation.errors}")

    schema_model = SchemaModel(schema)
    environments = list(schema_model.environments())
    if not environments:
        raise InvalidPolicy("The schema has no applicable request environments")

    for count, (principal, action, resource) in enumerate(environments, start=1):
        env = Environment(schema_model, principal, action, resource)
        allow_a, allow_b = (_allow(tree, env) for tree in trees)
        env.finalize()
        solver = z3.Solver()
        if timeout_ms is not None:
            solver.set(timeout=timeout_ms)
        # The negation of A => B is A AND NOT B, not XOR or NOT A AND B.
        solver.add(*env.constraints, allow_a, z3.Not(allow_b))
        answer = solver.check()
        if answer == z3.unsat:
            continue
        if answer != z3.sat:
            raise SolverError(f"Z3 returned {answer}: {solver.reason_unknown()}")
        request, entities = Materializer(env, solver.model(), timeout_ms).build()
        try:
            # This independently checks schema validity and hierarchy closure.
            checked_entities = cedarpy.Entities.from_json_str(json.dumps(entities), schema=cedar_schema)
            decision_a = cedarpy.is_authorized(request, parsed_a, checked_entities, schema=cedar_schema)
            decision_b = cedarpy.is_authorized(request, parsed_b, checked_entities, schema=cedar_schema)
        except (ValueError, TypeError) as error:
            raise CounterexampleError(f"Generated data failed Cedar validation: {error}") from error
        if decision_a.decision != cedarpy.Decision.Allow or decision_b.decision != cedarpy.Decision.Deny:
            raise CounterexampleError(
                "The symbolic model did not replay as Allow(A) and Deny(B); no answer was returned"
            )
        return ImplicationResult(False, Counterexample(request, entities), count)
    return ImplicationResult(True, None, len(environments))


def is_at_least_as_conservative(
    policy_a: str,
    policy_b: str,
    schema: dict[str, Any],
    *,
    base_policies: str = "",
    timeout_ms: int | None = None,
) -> bool:
    """Boolean convenience API; see check_implication() for counterexamples."""
    return check_implication(
        policy_a, policy_b, schema,
        base_policies=base_policies, timeout_ms=timeout_ms,
    ).holds
