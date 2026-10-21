"""Schema-directed symbolic requests and entity data.

Only entity terms actually observed by the policies need to be materialized.
Functions preserve aliasing: two equal UIDs always have identical attributes.
Hierarchy constraints are generated over all observed UIDs, not independent
Boolean variables for each occurrence of Cedar's `in` operator.
"""
from __future__ import annotations

from dataclasses import replace
from itertools import count

import z3

from .model import (
    BOOL, EMPTY_SET, LONG_MAX, LONG_MIN, Field, Type, Value,
    UnsupportedFeature, sort_of, element_sort, set_member, string_literal,
    encoded_string_regex,
)


class Environment:
    def __init__(self, schema, principal_type: str, action: tuple[str, str], resource_type: str):
        self.schema = schema
        self.action = action
        self.constraints: list[z3.BoolRef] = []
        self._counter = count()
        self._functions = {}
        self._records = {}
        self.entity_terms: dict[tuple[str, str], Value] = {}
        self.scalar_terms: dict[Type, dict[str, Value]] = {}
        self.set_terms: dict[Type, dict[str, Value]] = {}
        self.variables = {
            "principal": self.entity(principal_type, z3.String("principal_id")),
            "action": self.entity(action[0], string_literal(action[1])),
            "resource": self.entity(resource_type, z3.String("resource_id")),
            "context": self.symbolic(schema.actions[action].context, ("context",)),
        }

    def fresh(self, label="v"):
        return f"{label}_{next(self._counter)}"

    def function(self, key, result_sort, *argument_sorts):
        if key not in self._functions:
            self._functions[key] = z3.Function(self.fresh("f"), *argument_sorts, result_sort)
        return self._functions[key]

    def observe(self, value: Value):
        if value.type.kind == "record":
            for field in value.data.values():
                self.observe(field.value)
        elif value.type.kind == "set":
            self.set_terms.setdefault(value.type.element, {})[value.data.sexpr()] = value
        elif value.type.kind not in {"empty_set"}:
            terms = self.scalar_terms.setdefault(value.type, {})
            key = value.data.sexpr()
            if value.type.kind == "string" and key not in terms:
                # Negated patterns must not admit strings outside the encoding
                # (e.g. an impossible witness for !(context.s like "*")).
                # Entity IDs and unobserved set members remain opaque: only
                # their equality is visible, so the materializer can rename
                # them injectively while preserving every observation.
                self.constraints.append(z3.InRe(value.data, encoded_string_regex()))
            terms[key] = value
            if value.type.kind == "entity":
                self.entity_terms[(value.type.name, value.data.sexpr())] = value

    def entity(self, type_name, id_expr, ok=None):
        if type_name not in self.schema.entities and not self.schema.is_action_type(type_name):
            raise UnsupportedFeature(f"Entity type {type_name!r} is not declared in the schema")
        value = Value(Type("entity", name=type_name), id_expr,
                      z3.BoolVal(True) if ok is None else ok)
        self.observe(value)
        return value

    def exists(self, value):
        if self.schema.is_action_type(value.type.name):
            return z3.Or(*[
                value.data == string_literal(uid[1])
                for uid in self.schema.actions if uid[0] == value.type.name
            ])
        return self.function(("exists", value.type.name), z3.BoolSort(), z3.StringSort())(value.data)

    def symbolic(self, ty, key, owner=None):
        def atom(atom_type, suffix):
            skey = key + (suffix,)
            if owner is None:
                return z3.Const(self.fresh("v"), sort_of(atom_type))
            return self.function(skey, sort_of(atom_type), z3.StringSort())(owner)

        if ty.kind == "record":
            fields = {}
            for name, field_type, required in ty.fields:
                value = self.symbolic(field_type, key + (name,), owner)
                present = z3.BoolVal(True) if required else atom(BOOL, name + ":present")
                fields[name] = Field(present, value)
            result = Value(ty, fields)
        else:
            result = Value(ty, atom(ty, "value"))
            if ty.kind == "long":
                self.constraints.extend([result.data >= LONG_MIN, result.data <= LONG_MAX])
            elif ty.kind == "entity" and self.schema.is_action_type(ty.name):
                ids = [uid[1] for uid in self.schema.actions if uid[0] == ty.name]
                if not ids:
                    raise UnsupportedFeature("Action-valued attributes require a nonempty declared action type")
                self.constraints.append(z3.Or(*[result.data == string_literal(uid) for uid in ids]))
            elif (ty.kind == "set" and ty.element.kind == "entity"
                  and self.schema.is_action_type(ty.element.name)):
                # Unlike ordinary entity IDs, schema-valid Action values come
                # from the finite collection of declared action UIDs.
                actions = z3.EmptySet(z3.StringSort())
                for uid in self.schema.actions:
                    if uid[0] == ty.element.name:
                        actions = z3.SetAdd(actions, string_literal(uid[1]))
                result = Value(ty, z3.SetIntersect(result.data, actions))
        self.observe(result)
        return result

    def record_for_entity(self, entity):
        if self.schema.is_action_type(entity.type.name):
            return Value(Type("record"), {}, z3.And(entity.ok, self.exists(entity)))
        key = (entity.type.name, entity.data.sexpr())
        if key not in self._records:
            self._records[key] = self.symbolic(
                self.schema.entities[entity.type.name],
                ("attributes", entity.type.name), entity.data,
            )
        record = self._records[key]
        return replace(record, ok=z3.And(entity.ok, self.exists(entity)))

    def get_attr(self, base, name):
        if base.type.kind == "entity":
            base = self.record_for_entity(base)
        if base.type.kind != "record":
            raise UnsupportedFeature("Attribute access requires an entity or a record")
        if name not in base.data:
            raise UnsupportedFeature(f"Attribute {name!r} is not available in this request environment")
        field = base.data[name]
        return replace(field.value, ok=z3.And(base.ok, field.present, field.value.ok))

    def _has_one(self, base, name):
        if base.type.kind == "entity":
            record = self.record_for_entity(base)
            field = record.data.get(name)
            present = z3.BoolVal(False) if field is None else field.present
            # Unlike attribute access, `has` on an absent entity is false.
            return Value(BOOL, z3.And(self.exists(base), present), base.ok)
        if base.type.kind == "record":
            field = base.data.get(name)
            return Value(BOOL, z3.BoolVal(False) if field is None else field.present, base.ok)
        raise UnsupportedFeature("has requires an entity or a record")

    def has_attr(self, base, names):
        result = z3.BoolVal(True)
        ok = z3.BoolVal(True)
        current = base
        for index, name in enumerate(names):
            part = self._has_one(current, name)
            ok = z3.And(ok, z3.Implies(result, part.ok))
            result = z3.simplify(z3.And(result, part.data))
            if z3.is_false(result):
                break
            if index < len(names) - 1:
                current = self.get_attr(current, name)
        return Value(BOOL, result, ok)

    def make_set(self, members):
        if not members:
            return Value(EMPTY_SET, None)
        ty = members[0].type
        if ty.kind not in {"bool", "long", "string", "entity"}:
            raise UnsupportedFeature("Sets of records or sets are not implemented")
        if any(member.type != ty for member in members):
            raise UnsupportedFeature("Heterogeneous sets are not implemented")
        data = z3.EmptySet(element_sort(ty))
        for member in members:
            data = z3.SetAdd(data, set_member(member))
        value = Value(Type("set", element=ty), data, z3.And(*[x.ok for x in members]))
        self.observe(value)
        return value

    def strict_ancestor(self, left, right):
        lt, rt = left.type.name, right.type.name
        if self.schema.is_action_type(lt) or self.schema.is_action_type(rt):
            return z3.Or(*[
                z3.And(left.data == string_literal(uid[1]),
                       right.data == string_literal(parent[1]))
                for uid, spec in self.schema.actions.items() if uid[0] == lt
                for parent in spec.parents if parent[0] == rt and parent != uid
            ])
        if rt not in self.schema.ancestor_types.get(lt, ()):
            return z3.BoolVal(False)
        return self.function(("ancestor", lt, rt), z3.BoolSort(),
                             z3.StringSort(), z3.StringSort())(left.data, right.data)

    def in_entity(self, left, right):
        if left.type.kind != "entity" or right.type.kind != "entity":
            raise UnsupportedFeature("Cedar in requires entity operands")
        same = (left.data == right.data) if left.type == right.type else z3.BoolVal(False)
        return Value(BOOL, z3.Or(same, self.strict_ancestor(left, right)), z3.And(left.ok, right.ok))

    def finalize(self):
        """Add graph axioms for all observed entities; never assume a fixed store."""
        terms = [v for v in self.entity_terms.values()
                 if not self.schema.is_action_type(v.type.name)]
        for left in terms:
            for right in terms:
                rel = self.strict_ancestor(left, right)
                if z3.is_false(rel):
                    continue
                lrank = self.function(("rank", left.type.name), z3.IntSort(), z3.StringSort())(left.data)
                rrank = self.function(("rank", right.type.name), z3.IntSort(), z3.StringSort())(right.data)
                self.constraints.append(z3.Implies(rel, z3.And(self.exists(left), lrank < rrank)))
                for end in terms:
                    next_rel = self.strict_ancestor(right, end)
                    if not z3.is_false(next_rel):
                        self.constraints.append(z3.Implies(
                            z3.And(rel, next_rel), self.strict_ancestor(left, end)))

