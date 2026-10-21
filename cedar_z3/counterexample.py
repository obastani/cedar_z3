"""Turn a satisfying Z3 model into finite Cedar JSON data.

Z3 represents sets as Boolean arrays, which can have infinite support. Cedar
only observes membership, equality, subset, intersection emptiness, and
emptiness. Projecting onto the scalar terms plus a witness for each relevant
nonempty intersection/difference preserves those observations and produces
finite sets without choosing an arbitrary size bound.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

import z3

from .model import (
    LONG_MAX, LONG_MIN, CounterexampleError, SolverError,
    Type, Value, sort_of, element_sort, set_member, string_literal,
)


@dataclass(frozen=True)
class _Text:
    key: str


class Materializer:
    def __init__(self, env, model, timeout_ms=None):
        self.env, self.model = env, model
        self.timeout_ms = timeout_ms
        self.texts: dict[str, str | None] = {}
        self.universes = {}
        self.arrays = {}

    def evaluate(self, expr):
        return self.model.eval(expr, model_completion=True)

    def truth(self, expr):
        value = self.evaluate(expr)
        if not z3.is_true(value) and not z3.is_false(value):
            raise CounterexampleError(f"Expected a concrete Boolean, got {value}")
        return z3.is_true(value)

    def text(self, value):
        value = z3.simplify(value)
        if not z3.is_string_value(value):
            raise CounterexampleError(f"Expected a concrete string, got {value}")
        key, raw = value.sexpr(), value.as_string()
        decoded = None
        if re.fullmatch(r"u(?:[0-9a-f]{2})*", raw):
            try:
                decoded = bytes.fromhex(raw[1:]).decode("utf-8")
            except UnicodeError:
                pass
        self.texts[key] = decoded
        return _Text(key)

    def scalar(self, ty, expr):
        value = self.evaluate(expr)
        if ty.kind == "bool":
            return self.truth(expr)
        if ty.kind == "long":
            if z3.is_bv_value(value):
                unsigned = value.as_long()
                return unsigned if unsigned < (1 << 63) else unsigned - (1 << 64)
            if not z3.is_int_value(value) or not LONG_MIN <= value.as_long() <= LONG_MAX:
                raise CounterexampleError(f"Invalid Cedar Long in model: {value}")
            return value.as_long()
        if ty.kind == "string":
            return self.text(value)
        if ty.kind == "entity":
            return {"__entity": {"type": ty.name, "id": self.text(value)}}
        raise CounterexampleError(f"Unsupported scalar type in model: {ty}")

    def ground_array(self, expr):
        value = self.evaluate(expr)
        if z3.is_as_array(value):
            interpretation = self.model[z3.get_as_array_func(value)]
            if interpretation is None:
                raise CounterexampleError("Z3 returned an uninterpreted array")
            x = z3.Const(self.env.fresh("array_arg"), value.sort().domain())
            body = z3.substitute_vars(interpretation.else_value(), x)
            for index in reversed(range(interpretation.num_entries())):
                entry = interpretation.entry(index)
                body = z3.If(x == entry.arg_value(0), entry.value(), body)
            value = z3.Lambda(x, body)
        return value

    def project_sets(self):
        for ty, scalar_terms in self.env.scalar_terms.items():
            # Reserve all literal/model strings before choosing fresh names.
            if ty.kind in {"string", "entity"}:
                for scalar in scalar_terms.values():
                    self.text(self.evaluate(scalar.data))

        for ty, set_terms in self.env.set_terms.items():
            universe = {
                self.evaluate(set_member(value)).sexpr(): self.evaluate(set_member(value))
                for value in self.env.scalar_terms.get(ty, {}).values()
            }
            arrays = {}
            for original, value in set_terms.items():
                array = self.ground_array(value.data)
                self.arrays[original] = array
                arrays[array.sexpr()] = array
            arrays = list(arrays.values())
            witness = z3.Const(self.env.fresh("set_witness"), element_sort(ty))
            solver = z3.Solver()
            if self.timeout_ms is not None:
                solver.set(timeout=self.timeout_ms)

            def add_witness(predicate):
                solver.push()
                try:
                    solver.add(predicate)
                    answer = solver.check()
                    if answer == z3.unknown:
                        raise SolverError("Set witness query: " + solver.reason_unknown())
                    if answer == z3.sat:
                        member = solver.model().eval(witness, model_completion=True)
                        universe[member.sexpr()] = member
                finally:
                    solver.pop()

            for array in arrays:
                add_witness(z3.IsMember(witness, array))
            for index, left in enumerate(arrays):
                for right in arrays[index + 1:]:
                    lm, rm = z3.IsMember(witness, left), z3.IsMember(witness, right)
                    add_witness(z3.And(lm, z3.Not(rm)))
                    add_witness(z3.And(rm, z3.Not(lm)))
                    add_witness(z3.And(lm, rm))
            self.universes[ty] = list(universe.values())

    def value(self, value):
        ty = value.type
        if ty.kind == "record":
            return {name: self.value(field.value) for name, field in value.data.items()
                    if self.truth(field.present)}
        if ty.kind == "empty_set":
            return []
        if ty.kind == "set":
            array = self.arrays[value.data.sexpr()]
            result = []
            for member in self.universes[ty.element]:
                membership = z3.simplify(z3.IsMember(member, array))
                if not (z3.is_true(membership) or z3.is_false(membership)):
                    membership = self.evaluate(membership)
                if z3.is_true(membership):
                    result.append(self.scalar(ty.element, member))
                elif not z3.is_false(membership):
                    raise CounterexampleError("Could not evaluate projected set membership")
            return result
        return self.scalar(ty, value.data)

    def default(self, ty):
        if ty.kind == "record":
            return {name: self.default(child) for name, child, required in ty.fields if required}
        if ty.kind == "set":
            return []
        if ty.kind == "bool":
            return False
        if ty.kind == "long":
            return 0
        if ty.kind == "string":
            return self.text(string_literal(""))
        if ty.kind == "entity":
            identifier = ""
            if self.env.schema.is_action_type(ty.name):
                identifiers = [uid[1] for uid in self.env.schema.actions if uid[0] == ty.name]
                if not identifiers:
                    raise CounterexampleError("No declared action can populate a required Action attribute")
                identifier = sorted(identifiers)[0]
            return {"__entity": {"type": ty.name, "id": self.text(string_literal(identifier))}}
        raise CounterexampleError(f"No default for type {ty}")

    def build(self):
        self.project_sets()
        env = self.env
        terms = list(env.entity_terms.values())
        # Resolve cached records by concrete UID too, preserving symbolic aliases.
        records = {}
        for (type_name, expr_key), record in env._records.items():
            entity = env.entity_terms[(type_name, expr_key)]
            records[(type_name, self.evaluate(entity.data).sexpr())] = record

        entities = {}
        for entity in terms:
            if env.schema.is_action_type(entity.type.name) or not self.truth(env.exists(entity)):
                continue
            raw_id = self.evaluate(entity.data)
            key = (entity.type.name, raw_id.sexpr())
            if key in entities:
                continue
            record = records.get(key)
            attrs = self.value(record) if record is not None else self.default(env.schema.entities[key[0]])
            parents = {}
            for parent in terms:
                if self.truth(env.strict_ancestor(entity, parent)):
                    parent_id = self.evaluate(parent.data)
                    parents[(parent.type.name, parent_id.sexpr())] = {
                        "type": parent.type.name, "id": self.text(parent_id),
                    }
            entities[key] = {
                "uid": {"type": key[0], "id": self.text(raw_id)},
                "attrs": attrs,
                "parents": list(parents.values()),
            }
        # Include the action hierarchy so the example is usable without a
        # caller having to separately hydrate schema-defined action entities.
        for uid, action in env.schema.actions.items():
            entities[(uid[0], "action:" + uid[1])] = {
                "uid": {"type": uid[0], "id": self.text(string_literal(uid[1]))},
                "attrs": {},
                "parents": [
                    {"type": p[0], "id": self.text(string_literal(p[1]))}
                    for p in sorted(action.parents) if p != uid
                ],
            }
        request = {
            name: {"type": env.variables[name].type.name,
                   "id": self.text(self.evaluate(env.variables[name].data))}
            for name in ("principal", "action", "resource")
        }
        request["context"] = self.value(env.variables["context"])

        names = {key: value for key, value in self.texts.items() if value is not None}
        used = set(names.values())
        index = 0
        for key in sorted(self.texts):
            if key in names:
                continue
            while f"__z3_{index}" in used:
                index += 1
            names[key] = f"__z3_{index}"
            used.add(names[key])
            index += 1

        def resolve(obj):
            if isinstance(obj, _Text):
                return names[obj.key]
            if isinstance(obj, dict):
                return {key: resolve(value) for key, value in obj.items()}
            if isinstance(obj, list):
                return [resolve(value) for value in obj]
            return obj

        return resolve(request), resolve(list(entities.values()))
