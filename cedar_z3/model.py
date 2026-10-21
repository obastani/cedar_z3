"""Small typed intermediate representation used by the Cedar/Z3 encoder."""
from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

import z3


class CedarImplicationError(Exception):
    """The comparison could not be completed; no Boolean answer is implied."""


class UnsupportedFeature(CedarImplicationError):
    """A Cedar construct outside the implemented fragment was encountered."""


class InvalidPolicy(CedarImplicationError):
    """A policy or schema failed Cedar parsing or validation."""


class SolverError(CedarImplicationError):
    """Z3 did not return sat or unsat."""


class CounterexampleError(CedarImplicationError):
    """A symbolic model could not be converted to a verified Cedar example."""


@dataclass(frozen=True)
class Type:
    kind: str
    name: str = ""
    fields: tuple[tuple[str, Type, bool], ...] = ()
    element: Type | None = None


BOOL = Type("bool")
LONG = Type("long")
STRING = Type("string")
EMPTY_SET = Type("empty_set")
LONG_MIN = -(1 << 63)
LONG_MAX = (1 << 63) - 1


def string_literal(value: str) -> z3.SeqRef:
    """Injectively encode Cedar strings, including all Unicode scalars.

    UTF-8 hex encoding avoids Z3's smaller character alphabet and its
    interpretation of backslash-u sequences in StringVal(). Pattern matching
    operates on this same encoding, at complete Unicode scalar boundaries.
    """
    return z3.StringVal("u" + value.encode("utf-8").hex())


@lru_cache(maxsize=1)
def encoded_character_regex() -> z3.ReRef:
    """The UTF-8 hex encodings of exactly one Unicode scalar value.

    Restricting UTF-8 leading/continuation bytes excludes overlong sequences,
    surrogates, and code points above U+10FFFF. A wildcard must consume complete
    scalars, rather than arbitrary hex digits or partial UTF-8 sequences.
    """
    hexdigit = z3.Union(z3.Range("0", "9"), z3.Range("a", "f"))
    continuation = z3.Concat(
        z3.Union(z3.Range("8", "9"), z3.Range("a", "b")), hexdigit,
    )
    two_byte_lead = z3.Union(
        z3.Concat(z3.Re("c"), z3.Union(z3.Range("2", "9"), z3.Range("a", "f"))),
        z3.Concat(z3.Re("d"), hexdigit),
    )
    return z3.Union(
        # U+0000..U+007F.
        z3.Concat(z3.Range("0", "7"), hexdigit),
        # U+0080..U+07FF.
        z3.Concat(two_byte_lead, continuation),
        # U+0800..U+FFFF, excluding UTF-16 surrogates.
        z3.Concat(z3.Re("e0"), z3.Range("a", "b"), hexdigit, continuation),
        z3.Concat(z3.Re("e"), z3.Union(z3.Range("1", "9"), z3.Range("a", "c")),
                  continuation, continuation),
        z3.Concat(z3.Re("ed"), z3.Range("8", "9"), hexdigit, continuation),
        z3.Concat(z3.Re("e"), z3.Range("e", "f"), continuation, continuation),
        # U+10000..U+10FFFF.
        z3.Concat(z3.Re("f0"), z3.Union(z3.Re("9"), z3.Range("a", "b")),
                  hexdigit, continuation, continuation),
        z3.Concat(z3.Re("f"), z3.Range("1", "3"),
                  continuation, continuation, continuation),
        z3.Concat(z3.Re("f48"), hexdigit, continuation, continuation),
    )


@lru_cache(maxsize=1)
def encoded_string_regex() -> z3.ReRef:
    """All encoded Cedar strings, including the empty string encoded as 'u'."""
    return z3.Concat(z3.Re("u"), z3.Star(encoded_character_regex()))


@dataclass
class Value:
    type: Type
    data: Any
    ok: z3.BoolRef = field(default_factory=lambda: z3.BoolVal(True))


@dataclass
class Field:
    present: z3.BoolRef
    value: Value


def sort_of(ty: Type) -> z3.SortRef:
    if ty.kind == "bool":
        return z3.BoolSort()
    if ty.kind == "long":
        return z3.IntSort()
    if ty.kind in ("string", "entity"):
        return z3.StringSort()
    if ty.kind == "set" and ty.element is not None:
        if ty.element.kind not in {"bool", "long", "string", "entity"}:
            raise UnsupportedFeature("Sets of records or sets are not implemented")
        return z3.SetSort(element_sort(ty.element))
    raise UnsupportedFeature(f"Cannot create a Z3 sort for {ty}")


def element_sort(ty: Type) -> z3.SortRef:
    # A Long-valued set has exactly 2**64 possible elements. Using a finite
    # bitvector domain avoids quantifiers restricting arrays indexed by Int.
    return z3.BitVecSort(64) if ty.kind == "long" else sort_of(ty)


def set_member(value: Value) -> z3.ExprRef:
    return z3.Int2BV(value.data, 64) if value.type.kind == "long" else value.data


def eq_values(a: Value, b: Value) -> Value:
    """Cedar equality, with errors propagated separately from truth values."""
    ok = z3.And(a.ok, b.ok)
    if a.type.kind == b.type.kind == "record":
        conditions = []
        for name in sorted(a.data.keys() | b.data.keys()):
            af, bf = a.data.get(name), b.data.get(name)
            if af is None:
                conditions.append(z3.Not(bf.present))
            elif bf is None:
                conditions.append(z3.Not(af.present))
            else:
                equality = eq_values(af.value, bf.value)
                both_present = z3.And(af.present, bf.present)
                conditions.extend([
                    af.present == bf.present,
                    z3.Implies(both_present, equality.data),
                ])
                ok = z3.And(ok, z3.Implies(both_present, equality.ok))
        return Value(BOOL, z3.And(*conditions), ok)
    if a.type.kind == b.type.kind == "empty_set":
        return Value(BOOL, z3.BoolVal(True), ok)
    if a.type.kind == "empty_set" and b.type.kind == "set":
        return Value(BOOL, b.data == z3.EmptySet(element_sort(b.type.element)), ok)
    if b.type.kind == "empty_set" and a.type.kind == "set":
        return eq_values(b, a)
    if a.type != b.type:
        # Nonempty heterogeneous entity sets have no common members. Empty
        # sets compare equal regardless of the types inferred for their items.
        if a.type.kind == b.type.kind == "set":
            return Value(BOOL, z3.And(
                a.data == z3.EmptySet(element_sort(a.type.element)),
                b.data == z3.EmptySet(element_sort(b.type.element)),
            ), ok)
        return Value(BOOL, z3.BoolVal(False), ok)
    return Value(BOOL, a.data == b.data, ok)


def merge_values(condition: z3.BoolRef, a: Value, b: Value) -> Value:
    """A typed, lazy if-expression; the caller adds the condition's validity."""
    ok = z3.If(condition, a.ok, b.ok)
    if a.type.kind == b.type.kind == "empty_set":
        return Value(EMPTY_SET, None, ok)
    if a.type.kind == "empty_set" and b.type.kind == "set":
        a = Value(b.type, z3.EmptySet(element_sort(b.type.element)), a.ok)
    if b.type.kind == "empty_set" and a.type.kind == "set":
        b = Value(a.type, z3.EmptySet(element_sort(a.type.element)), b.ok)
    if a.type.kind == b.type.kind == "record":
        fields = {}
        field_types = []
        for name in sorted(a.data.keys() | b.data.keys()):
            af, bf = a.data.get(name), b.data.get(name)
            if af is None:
                value = bf.value
                present = z3.And(z3.Not(condition), bf.present)
            elif bf is None:
                value = af.value
                present = z3.And(condition, af.present)
            else:
                value = merge_values(condition, af.value, bf.value)
                present = z3.If(condition, af.present, bf.present)
            fields[name] = Field(present, value)
            field_types.append((name, value.type, False))
        return Value(Type("record", fields=tuple(field_types)), fields, ok)
    if a.type != b.type:
        raise UnsupportedFeature(
            "Conditional branches with different scalar/entity types are not implemented"
        )
    return Value(a.type, z3.If(condition, a.data, b.data), ok)
