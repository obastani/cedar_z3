"""Translate the supported Cedar PST expressions into typed Z3 values.

``Value.ok`` is the success condition for evaluation.  In particular, an
erroneous Boolean expression is not replaced with the Boolean value false:
that would make negation, ``unless``, and short circuiting unsound.
"""

from __future__ import annotations

from typing import Any

import z3
from cedarpy import pst

from .model import (
    BOOL,
    LONG,
    STRING,
    Field,
    Type,
    UnsupportedFeature,
    Value,
    eq_values,
    merge_values,
    set_member,
    string_literal,
)


MIN_LONG = -(1 << 63)
MAX_LONG = (1 << 63) - 1


def _and(*conditions: Any) -> z3.BoolRef:
    return z3.And(*conditions)


def _constant_bool(expr: Any) -> bool | None:
    simplified = z3.simplify(expr)
    if z3.is_true(simplified):
        return True
    if z3.is_false(simplified):
        return False
    return None


def _require(value: Value, expected: Type, operation: str) -> None:
    if value.type != expected:
        raise UnsupportedFeature(
            f"{operation} requires {expected.kind}, got {value.type.kind}"
        )


def _require_set(value: Value, operation: str) -> None:
    if value.type.kind not in ("set", "empty_set"):
        raise UnsupportedFeature(
            f"{operation} requires a set, got {value.type.kind}"
        )


def _empty(value: Value) -> z3.BoolRef:
    """The value of isEmpty(); the caller carries value.ok separately."""
    _require_set(value, "isEmpty")
    if value.type.kind == "empty_set":
        return z3.BoolVal(True)
    return value.data == z3.EmptySet(value.data.sort().domain())


class ExpressionCompiler:
    """Compile expressions against one shared symbolic request/environment.

    ``env`` supplies variable, attribute, entity, hierarchy, and set handling.
    Both policies must use the same environment so shared entity attributes
    and request fields have the same interpretation.
    """

    def __init__(self, env: Any) -> None:
        self.env = env

    def compile(self, node: Any) -> Value:
        result = self._compile(node)
        self.env.observe(result)
        return result

    def _compile(self, node: Any) -> Value:
        if isinstance(node, pst.BoolLit):
            return Value(BOOL, z3.BoolVal(node.value))
        if isinstance(node, pst.LongLit):
            if not MIN_LONG <= node.value <= MAX_LONG:
                raise UnsupportedFeature("Cedar integer literal is outside signed 64-bit range")
            return Value(LONG, z3.IntVal(node.value))
        if isinstance(node, pst.StringLit):
            return Value(STRING, self._string(node.value))
        if isinstance(node, pst.EntityLit):
            return self.env.entity(str(node.value.type), self._string(node.value.id))
        if isinstance(node, pst.Var):
            try:
                return self.env.variables[node.name]
            except KeyError as error:
                raise UnsupportedFeature(f"Unknown Cedar variable {node.name!r}") from error
        if isinstance(node, pst.GetAttr):
            return self.env.get_attr(self.compile(node.base), node.attr)
        if isinstance(node, pst.HasAttr):
            return self.env.has_attr(self.compile(node.base), node.attrs)
        if isinstance(node, pst.UnaryOp):
            return self._unary(node)
        if isinstance(node, pst.BinaryOp):
            return self._binary(node)
        if isinstance(node, pst.IfThenElse):
            return self._conditional(node)
        if isinstance(node, pst.Is):
            return self._is(node)
        if isinstance(node, pst.Set):
            if not node.elements:
                return Value(Type("empty_set"), None)
            return self.env.make_set([self.compile(item) for item in node.elements])
        if isinstance(node, pst.Record):
            fields = {name: self.compile(expr) for name, expr in node.fields.items()}
            record_type = Type(
                "record",
                fields=tuple((name, value.type, True) for name, value in sorted(fields.items())),
            )
            return Value(
                record_type,
                {
                    name: Field(z3.BoolVal(True), value)
                    for name, value in fields.items()
                },
                _and(*(value.ok for value in fields.values())),
            )
        if isinstance(node, pst.Like):
            raise UnsupportedFeature("The Cedar 'like' operator is not supported")
        if isinstance(node, pst.Slot):
            raise UnsupportedFeature("Unlinked Cedar template slots are not supported")
        raise UnsupportedFeature(f"Unsupported Cedar expression node: {type(node).__name__}")

    @staticmethod
    def _string(value: str) -> z3.SeqRef:
        # Strings are opaque in the supported fragment.  The shared injective
        # encoding preserves equality without Z3's alphabet/escape pitfalls.
        return string_literal(value)

    def _unary(self, node: pst.UnaryOp) -> Value:
        operation = node.op
        if operation not in ("not", "neg", "is_empty"):
            raise UnsupportedFeature(f"Unsupported Cedar unary operation: {operation}")
        value = self.compile(node.arg)
        if operation == "not":
            _require(value, BOOL, "!")
            return Value(BOOL, z3.Not(value.data), value.ok)
        if operation == "neg":
            _require(value, LONG, "unary -")
            result = -value.data
            return Value(LONG, result, _and(value.ok, result >= MIN_LONG, result <= MAX_LONG))
        return Value(BOOL, _empty(value), value.ok)

    def _binary(self, node: pst.BinaryOp) -> Value:
        operation = node.op
        if operation in ("and", "or"):
            return self._logical(node)
        supported = {
            "eq", "not_eq", "less", "less_eq", "greater", "greater_eq",
            "add", "sub", "mul", "in", "contains", "contains_all", "contains_any",
        }
        if operation not in supported:
            raise UnsupportedFeature(f"Unsupported Cedar binary operation: {operation}")
        if operation == "in" and isinstance(node.right, pst.Set):
            left = self.compile(node.left)
            # A Cedar set literal is evaluated eagerly: a later erroneous
            # member still causes an error even if an earlier member matches.
            members = [self.compile(item) for item in node.right.elements]
            if left.type.kind != "entity":
                raise UnsupportedFeature("Cedar in requires an entity on its left")
            matches = [self.env.in_entity(left, member) for member in members]
            return Value(
                BOOL,
                z3.Or(*(match.data for match in matches)),
                _and(left.ok, *(member.ok for member in members)),
            )
        left, right = self.compile(node.left), self.compile(node.right)
        if operation in ("eq", "not_eq"):
            equal = eq_values(left, right)
            return equal if operation == "eq" else Value(BOOL, z3.Not(equal.data), equal.ok)
        if operation == "in":
            if right.type.kind in ("set", "empty_set"):
                raise UnsupportedFeature(
                    "Cedar in with a symbolic RHS set is not supported; use an entity or a set literal"
                )
            return self.env.in_entity(left, right)
        if operation in ("contains", "contains_all", "contains_any"):
            return self._set_operation(operation, left, right)
        _require(left, LONG, operation)
        _require(right, LONG, operation)
        ok = _and(left.ok, right.ok)
        if operation == "less":
            return Value(BOOL, left.data < right.data, ok)
        if operation == "less_eq":
            return Value(BOOL, left.data <= right.data, ok)
        if operation == "greater":
            return Value(BOOL, left.data > right.data, ok)
        if operation == "greater_eq":
            return Value(BOOL, left.data >= right.data, ok)
        if operation == "add":
            result = left.data + right.data
        elif operation == "sub":
            result = left.data - right.data
        else:
            result = left.data * right.data
        return Value(LONG, result, _and(ok, result >= MIN_LONG, result <= MAX_LONG))

    def _logical(self, node: pst.BinaryOp) -> Value:
        left = self.compile(node.left)
        _require(left, BOOL, node.op)
        constant = _constant_bool(left.data)
        if node.op == "and" and constant is False:
            return Value(BOOL, z3.BoolVal(False), left.ok)
        if node.op == "or" and constant is True:
            return Value(BOOL, z3.BoolVal(True), left.ok)
        right = self.compile(node.right)
        _require(right, BOOL, node.op)
        if node.op == "and":
            # Evaluate RHS only if LHS successfully evaluates to true.
            ok = _and(left.ok, z3.Or(z3.Not(left.data), right.ok))
            data = z3.And(left.data, right.data)
        else:
            # Evaluate RHS only if LHS successfully evaluates to false.
            ok = _and(left.ok, z3.Or(left.data, right.ok))
            data = z3.Or(left.data, right.data)
        return Value(BOOL, data, ok)

    def _conditional(self, node: pst.IfThenElse) -> Value:
        condition = self.compile(node.cond)
        _require(condition, BOOL, "if")
        constant = _constant_bool(condition.data)
        if constant is not None:
            selected = self.compile(node.then_expr if constant else node.else_expr)
            return Value(selected.type, selected.data, _and(condition.ok, selected.ok))
        then_value = self.compile(node.then_expr)
        else_value = self.compile(node.else_expr)
        merged = merge_values(condition.data, then_value, else_value)
        return Value(merged.type, merged.data, _and(condition.ok, merged.ok))

    def _is(self, node: pst.Is) -> Value:
        value = self.compile(node.base)
        if value.type.kind != "entity":
            raise UnsupportedFeature("Cedar 'is' requires an entity expression")
        matches = value.type.name == str(node.entity_type)
        if not matches or node.in_expr is None:
            return Value(BOOL, z3.BoolVal(matches), value.ok)
        right = self.compile(node.in_expr)
        return self.env.in_entity(value, right)

    @staticmethod
    def _set_operation(operation: str, left: Value, right: Value) -> Value:
        _require_set(left, operation)
        ok = _and(left.ok, right.ok)
        if operation == "contains":
            if left.type.kind == "empty_set" or left.type.element != right.type:
                return Value(BOOL, z3.BoolVal(False), ok)
            return Value(BOOL, z3.IsMember(set_member(right), left.data), ok)

        _require_set(right, operation)
        if operation == "contains_all":
            if right.type.kind == "empty_set":
                result = z3.BoolVal(True)
            elif left.type.kind == "empty_set" or left.type.element != right.type.element:
                result = _empty(right)
            else:
                result = z3.IsSubset(right.data, left.data)
        else:
            if (
                left.type.kind == "empty_set"
                or right.type.kind == "empty_set"
                or left.type.element != right.type.element
            ):
                result = z3.BoolVal(False)
            else:
                intersection = z3.SetIntersect(left.data, right.data)
                result = intersection != z3.EmptySet(left.data.sort().domain())
        return Value(BOOL, result, ok)
