"""Normalize the supported Cedar JSON schema into the encoder's type model.

Cedar itself parses and validates the schema before this module is called.
This layer deliberately rejects features the symbolic encoder cannot model.
It does not infer a finite domain for ordinary entity IDs or attributes.
"""
from __future__ import annotations

from dataclasses import dataclass
from itertools import product
from typing import Any, Iterator

from .model import BOOL, LONG, STRING, InvalidPolicy, Type, UnsupportedFeature


EntityUID = tuple[str, str]


@dataclass(frozen=True)
class ActionSpec:
    uid: EntityUID
    principals: tuple[str, ...]
    resources: tuple[str, ...]
    context: Type
    parents: frozenset[EntityUID]


def _qualify(namespace: str, name: str) -> str:
    return f"{namespace}::{name}" if namespace else name


def _object(value: Any, where: str) -> dict:
    if not isinstance(value, dict):
        raise InvalidPolicy(f"{where} must be a JSON object")
    return value


def _keys(value: dict, allowed: set[str], where: str) -> None:
    unknown = value.keys() - allowed
    if unknown:
        raise UnsupportedFeature(f"Unsupported schema keys in {where}: {sorted(unknown)}")


class SchemaModel:
    """An immutable-by-convention normalization of one validated JSON schema."""

    def __init__(self, raw: dict[str, Any]):
        self.raw = raw
        self.entities: dict[str, Type] = {}
        self.actions: dict[EntityUID, ActionSpec] = {}
        self.ancestor_types: dict[str, frozenset[str]] = {}
        self._entity_defs: dict[str, tuple[str, dict]] = {}
        self._common_defs: dict[str, tuple[str, dict]] = {}
        self._common_types: dict[str, Type] = {}
        self._resolving: set[str] = set()
        self._action_defs: dict[EntityUID, tuple[str, dict]] = {}
        self._action_types = {_qualify(namespace, "Action") for namespace in raw}

        # Register all declarations before resolving cross-namespace references.
        for namespace, declaration in raw.items():
            declaration = _object(declaration, f"namespace {namespace!r}")
            _keys(declaration, {"entityTypes", "actions", "commonTypes", "annotations"},
                  f"namespace {namespace!r}")
            for name, definition in _object(declaration.get("entityTypes", {}),
                                            "entityTypes").items():
                self._entity_defs[_qualify(namespace, name)] = (
                    namespace, _object(definition, f"entity {name!r}"))
            for name, definition in _object(declaration.get("commonTypes", {}),
                                            "commonTypes").items():
                self._common_defs[_qualify(namespace, name)] = (
                    namespace, _object(definition, f"common type {name!r}"))
            for identifier, definition in _object(declaration.get("actions", {}),
                                                  "actions").items():
                uid = (_qualify(namespace, "Action"), identifier)
                self._action_defs[uid] = (namespace, _object(definition, f"action {uid!r}"))

        # Reject unsupported declarations even when a policy never uses them.
        for name in self._common_defs:
            self._common(name)

        parent_types: dict[str, set[str]] = {}
        for name, (namespace, definition) in self._entity_defs.items():
            _keys(definition, {"shape", "memberOfTypes", "annotations"}, f"entity {name}")
            shape = self._type(definition.get("shape", {"type": "Record"}), namespace)
            if shape.kind != "record":
                raise InvalidPolicy(f"Entity {name} must have a record shape")
            self.entities[name] = shape
            parent_types[name] = set(self._entity_list(
                definition.get("memberOfTypes", []), namespace, f"parents of {name}",
                allow_actions=False))
        self.ancestor_types = self._closure(parent_types)

        direct_parents: dict[EntityUID, set[EntityUID]] = {}
        for uid, (namespace, definition) in self._action_defs.items():
            _keys(definition, {"appliesTo", "memberOf", "annotations"}, f"action {uid!r}")
            applies = definition.get("appliesTo")
            if "appliesTo" not in definition:
                principals, resources, context = (), (), Type("record")
            else:
                applies = _object(applies, f"appliesTo of {uid!r}")
                _keys(applies, {"principalTypes", "resourceTypes", "context"},
                      f"appliesTo of {uid!r}")
                if "principalTypes" not in applies or "resourceTypes" not in applies:
                    raise UnsupportedFeature(
                        "Each appliesTo must explicitly provide principalTypes and resourceTypes")
                principals = self._entity_list(applies["principalTypes"], namespace,
                                               f"principalTypes of {uid!r}")
                resources = self._entity_list(applies["resourceTypes"], namespace,
                                              f"resourceTypes of {uid!r}")
                context = self._type(applies.get("context", {"type": "Record"}), namespace)
                if context.kind != "record":
                    raise InvalidPolicy(f"Context of {uid!r} must be a record")
            members = definition.get("memberOf", [])
            if not isinstance(members, list):
                raise InvalidPolicy(f"memberOf of {uid!r} must be an array")
            parents: set[EntityUID] = set()
            for parent in members:
                parent = _object(parent, f"parent action of {uid!r}")
                _keys(parent, {"type", "id"}, f"parent action of {uid!r}")
                if not isinstance(parent.get("id"), str):
                    raise InvalidPolicy("An action parent must have a string id")
                parent_type = (_qualify(namespace, "Action") if "type" not in parent
                               else self._resolve_entity(parent["type"], namespace))
                parent_uid = (parent_type, parent["id"])
                if parent_uid not in self._action_defs:
                    raise InvalidPolicy(f"Undeclared action parent {parent_uid!r}")
                parents.add(parent_uid)
            direct_parents[uid] = parents
            self.actions[uid] = ActionSpec(uid, principals, resources, context, frozenset())
        closure = self._closure(direct_parents)
        for uid, spec in self.actions.items():
            if uid in closure[uid]:
                raise InvalidPolicy("Action hierarchy contains a cycle")
            self.actions[uid] = ActionSpec(
                uid, spec.principals, spec.resources, spec.context, closure[uid])

    @staticmethod
    def _closure(graph: dict) -> dict:
        """Positive transitive closure; self occurs only along a real cycle."""
        closure = {}
        for source in graph:
            reached, todo = set(), list(graph[source])
            while todo:
                target = todo.pop()
                if target in reached:
                    continue
                reached.add(target)
                todo.extend(graph.get(target, ()))
            closure[source] = frozenset(reached)
        return closure

    @staticmethod
    def _candidates(name: str, namespace: str) -> tuple[str, ...]:
        if not isinstance(name, str):
            raise InvalidPolicy("Schema type names must be strings")
        if "::" in name or not namespace:
            return (name,)
        # Cedar resolves a local name in the current and empty namespaces;
        # the lexical prefixes of a nested namespace are not searched.
        return (_qualify(namespace, name), name)

    def _resolve_entity(self, name: str, namespace: str) -> str:
        for candidate in self._candidates(name, namespace):
            if candidate in self._entity_defs or candidate in self._action_types:
                return candidate
        raise InvalidPolicy(f"Unresolved entity type {name!r} in namespace {namespace!r}")

    def _entity_list(self, names, namespace, where, *, allow_actions=True):
        if not isinstance(names, list):
            raise UnsupportedFeature(f"{where} must be an explicit array of entity types")
        resolved = tuple(dict.fromkeys(self._resolve_entity(name, namespace) for name in names))
        if not allow_actions and any(self.is_action_type(name) for name in resolved):
            raise UnsupportedFeature("Ordinary entities cannot have Action parents")
        return resolved

    def _common(self, name: str) -> Type:
        if name in self._common_types:
            return self._common_types[name]
        if name in self._resolving:
            raise InvalidPolicy(f"Cyclic common type definition involving {name}")
        namespace, definition = self._common_defs[name]
        self._resolving.add(name)
        try:
            result = self._type(definition, namespace)
        finally:
            self._resolving.remove(name)
        self._common_types[name] = result
        return result

    def _type(self, definition, namespace) -> Type:
        definition = _object(definition, "type definition")
        kind = definition.get("type")
        if not isinstance(kind, str):
            raise InvalidPolicy("Every type definition must have a string type")
        common_keys = {"type", "required", "annotations"}
        primitives = {"Boolean": BOOL, "Bool": BOOL, "Long": LONG, "String": STRING}
        if kind in primitives:
            _keys(definition, common_keys, f"{kind} definition")
            return primitives[kind]
        if kind == "Record":
            _keys(definition, common_keys | {"attributes", "additionalAttributes"}, "record")
            if definition.get("additionalAttributes", False) is not False:
                raise UnsupportedFeature("Open records (additionalAttributes) are not implemented")
            fields = []
            attributes = _object(definition.get("attributes", {}), "record attributes")
            for name, attribute in sorted(attributes.items()):
                attribute = _object(attribute, f"attribute {name!r}")
                required = attribute.get("required", True)
                if type(required) is not bool:
                    raise InvalidPolicy(f"required of attribute {name!r} must be Boolean")
                fields.append((name, self._type(attribute, namespace), required))
            return Type("record", fields=tuple(fields))
        if kind == "Set":
            _keys(definition, common_keys | {"element"}, "set")
            element = self._type(definition.get("element"), namespace)
            if element.kind not in {"bool", "long", "string", "entity"}:
                raise UnsupportedFeature("Sets of records or sets are not implemented")
            return Type("set", element=element)
        if kind == "Entity":
            _keys(definition, common_keys | {"name"}, "entity reference")
            return Type("entity", name=self._resolve_entity(definition.get("name"), namespace))
        if kind == "Extension":
            raise UnsupportedFeature("Cedar extension types are not implemented")
        if kind == "EntityOrCommon":
            _keys(definition, common_keys | {"name"}, "entity or common type reference")
            name = definition.get("name")
        else:
            _keys(definition, common_keys, "common type reference")
            name = kind
        for candidate in self._candidates(name, namespace):
            if candidate in self._common_defs:
                return self._common(candidate)
        if kind == "EntityOrCommon":
            return Type("entity", name=self._resolve_entity(name, namespace))
        if name in {"ipaddr", "decimal", "datetime", "duration"}:
            raise UnsupportedFeature("Cedar extension types are not implemented")
        raise InvalidPolicy(f"Unresolved common type {name!r} in namespace {namespace!r}")

    def is_action_type(self, name: str) -> bool:
        return name in self._action_types

    def environments(self) -> Iterator[tuple[str, EntityUID, str]]:
        for uid, action in self.actions.items():
            for principal, resource in product(action.principals, action.resources):
                yield principal, uid, resource
