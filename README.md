# Warning

This project was generated one-shot using GPT-6-Astra. It is intended for internal use but was convenient to host on a publicly available Git repo. Use at your own risk.

# Cedar policy implication with Python and Z3

This package checks whether **policy set A is at least as conservative as policy
set B**:

```
for every schema-conforming request R and finite entity store E:
    Allow(A, R, E) implies Allow(B, R, E)
```

It searches for a counterexample to that statement:

```
Allow(A, R, E) AND NOT Allow(B, R, E)
```

An `unsat` result proves implication in the modeled domain. A `sat` result is
converted into a concrete request and entity store, then replayed with Cedar.
The checker returns `False` only after Cedar confirms that A allows and B denies
that same input.

**Runtime dependencies are only `cedarpy` and `z3-solver`.** There is no Cedar
Symbolic Compiler, CVC5, Cedar CLI, Rust build, or external solver process in
this implementation. Cedar-py supplies the Rust Cedar parser, validator, typed
policy syntax tree, and concrete evaluator; Python performs the translation
from that tree to Z3.

## Install and run

Use Python 3.10 or later on a platform supported by the dependencies.

```bash
python -m pip install -r requirements.txt
python example.py
python -m unittest discover -s tests -v
```

Alternatively, install this directory as a package with `python -m pip install .`.
The tested versions are `cedarpy==4.12.2` and `z3-solver==5.3.1.0`, on Python
3.12.14. Cedar-py 4.12.2 uses the Cedar 4.12 language engine. Dependency versions
are pinned because the typed syntax-tree interface follows the Cedar engine.

## Boolean API

```python
from cedar_z3 import is_at_least_as_conservative

answer: bool = is_at_least_as_conservative(policy_a, policy_b, schema)
```

`policy_a` and `policy_b` are Cedar source strings. Each can contain one policy,
multiple policies, or the empty policy set. `schema` is a standard Cedar JSON
schema dictionary. The example below is complete:

```python
from cedar_z3 import check_implication, is_at_least_as_conservative

schema = {
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

a = '''
permit(principal, action == Action::"read", resource)
when { context.clearance >= 5 };
'''
b = '''
permit(principal, action == Action::"read", resource)
when { context.clearance >= 3 };
'''

assert is_at_least_as_conservative(a, b, schema) is True
assert is_at_least_as_conservative(b, a, schema) is False

result = check_implication(b, a, schema)
print(result.holds)                    # False
print(result.counterexample.request)   # clearance is 3 or 4
print(result.counterexample.entities)
```

The counterexample is not guaranteed to be minimal, and its generated entity
IDs and other irrelevant values can differ between solver versions.

### Result with a counterexample

```python
check_implication(
    policy_a: str,
    policy_b: str,
    schema: dict,
    *,
    base_policies: str = "",
    timeout_ms: int | None = None,
) -> ImplicationResult
```

The result has:

- `holds: bool`.
- `counterexample: Counterexample | None` with `request`, `entities`,
  `decision_a="Allow"`, and `decision_b="Deny"` when implication fails.
- `environments_checked: int`, counting the action/principal-type/resource-type
  environments examined before returning.

`is_at_least_as_conservative()` has the same arguments and returns just
`check_implication(...).holds`.

There is no three-valued implication result. Invalid inputs and unsuccessful
execution raise exceptions. `timeout_ms=None`, the default, imposes no timeout.
If supplied, a positive timeout applies to each Z3 query, including finite-set
witness queries, rather than to the total call.

## What the schema means

The schema is part of the proposition being proved. Every declared combination
of action, permitted principal type, and permitted resource type is examined.
The checker does not enumerate a fixed collection of user/resource IDs or use
a sample entity store. Ordinary entity IDs and primitive attribute values are
symbolic; entity attributes, existence, optional fields, and hierarchy edges
are symbolic too. Action IDs and their ancestry come from the schema.

The result applies to requests and entity stores that conform to that schema.
It does not cover requests with undeclared actions, ill-typed data, extra
attributes excluded by the schema, or arbitrary application invariants that
were never supplied. A schema change can change the answer. Both policy sets
must pass Cedar's strict validation before encoding. A schema with no
applicable request environment is rejected rather than producing a vacuous
success that is easy to misinterpret.

## Cedar authorization semantics

For either policy set P, the encoded authorization decision is:

```
Allow(P) =
    OR(successful matches of permit policies)
    AND NOT OR(successful matches of forbid policies)
```

This preserves default deny, permit aggregation, forbid precedence, and
skip-on-error. Expressions carry a separate validity condition, so an error
does not become a Boolean `false` inside `!`, `unless`, or a conditional.
Short-circuiting is modeled. Cedar Long arithmetic has signed 64-bit bounds;
overflow makes evaluation fail instead of wrapping or becoming an unbounded
integer result.

### Comparing forbid rules

A policy set containing only forbids never grants a request, so two such
standalone sets both satisfy decision implication in both directions. To compare
restrictions against an existing permission baseline, supply that baseline:

```python
result = check_implication(
    'forbid(principal, action, resource) when { context.clearance < 5 };',
    'forbid(principal, action, resource) when { context.clearance < 3 };',
    schema,
    base_policies='permit(principal, action, resource);',
)
assert result.holds
```

This checks `Allow(base + A) => Allow(base + B)`. It compares the final
authorization decision, not whether the two policy bodies match the same
requests. It also does not compare diagnostic messages or determining policy
IDs. For equivalence, check implication in both directions.

## Implemented fragment and explicit boundaries

This is a direct implementation of a substantial, explicit Cedar fragment;
it is not a complete implementation of every Cedar feature.

Supported:

- Static `permit` and `forbid` policies, multiple `when`/`unless` clauses, and
  arbitrary policy sets.
- Principal/action/resource scopes using equality, hierarchy membership,
  type tests, and action lists; schema-defined action groups.
- Booleans, signed 64-bit integers, opaque strings, entity references, records,
  optional attributes, nested records, and sets of Boolean/Long/String/entity
  values.
- `==`, `!=`, integer comparisons, `+`, `-`, Cedar's restricted multiplication,
  unary minus, `!`, `&&`, `||`, and `if`/`then`/`else`.
- Attribute access, `has` paths, `is`, entity-to-entity `in`, and `in` with an
  explicit list of entity expressions.
- `contains`, `containsAll`, `containsAny`, `isEmpty`, set equality, and record
  equality.
- Namespaces, common schema type aliases, `EntityOrCommon`, entity hierarchy
  transitivity/reflexivity/acyclicity, missing entities, dangling parent
  references, and shared attributes when entity UIDs alias.

The following are explicitly rejected when encountered in the analyzed path
or schema:

- `like` and extension functions/types such as IP addresses, decimals, dates,
  and durations.
- Entity tags and tag operations, enum entity types, open records, unresolved
  external schema declarations, and unknown schema features.
- Templates and template-linked policies; provide fully instantiated static
  source policies instead.
- Sets of records, sets of sets, heterogeneous sets, and conditional branches
  with different scalar or entity types.
- `entity in context.someSet` and other symbolic sets on the right of `in`;
  explicit list RHS operands are supported. Ordinary set `.contains()` is
  supported and is different from hierarchy membership.
- `appliesTo` objects without explicit `principalTypes` and `resourceTypes`
  arrays. Actions with no `appliesTo` are treated as grouping actions.

Unreachable expression branches can be discarded after a statically decisive
scope or short-circuit condition. A rejected feature is never replaced with a
fresh Boolean, guessed translation, or successful proof.

### Exceptions

All checker-specific exceptions derive from `CedarImplicationError`:

| Exception | Meaning |
| --- | --- |
| `InvalidPolicy` | Cedar parsing/validation failed, the schema is invalid, or the request domain is empty. |
| `UnsupportedFeature` | An unsupported Cedar/schema construct was encountered. |
| `SolverError` | Z3 returned `unknown`, including a configured resource timeout. |
| `CounterexampleError` | A symbolic model could not be materialized and replayed as a valid Cedar counterexample. |

Ordinary argument misuse raises `TypeError` or `ValueError`. These are execution
failures, not additional logical outcomes. Decidability does not justify
interpreting a failed or interrupted solver execution as `True` or `False`.

## Encoding details

Both policy sets use the same `Environment`; principal/resource values,
attribute functions, presence bits, and hierarchy functions are shared. This
is essential: independent symbols for the same attribute would invalidate the
comparison.

Ordinary entity attributes are uninterpreted functions of typed entity IDs.
Entity existence is independent of the UID value. Hierarchy relations are
constrained by schema reachability, observed-term transitivity, and an integer
rank that prevents cycles. These constraints include every real finite
schema-conforming store. Satisfying models are materialized with the observed
ancestor links and checked by Cedar; model-decoding issues raise an exception.

Strings are opaque in the supported fragment. Literal strings and entity IDs
use an injective UTF-8 hex encoding, avoiding Z3's string escape handling and
its smaller character alphabet. The decoder assigns distinct Cedar strings to
distinct model values, preserving literal values. This is why adding a string
pattern or concatenation operator would require additional encoding work.

Sets are Z3 arrays. Long set elements use a 64-bit bitvector domain, while
scalar arithmetic uses bounded mathematical integers with explicit overflow
checks. Action-valued sets are restricted to declared action IDs. To obtain
finite Cedar sets from a model, the materializer retains relevant scalar
elements and a witness for each nonempty set/difference/intersection used by
the encoded values. This preserves the supported set observations without a
user-chosen cardinality bound.

The final solver query for each request environment is:

```python
solver.add(*env.constraints, allow_a, z3.Not(allow_b))
answer = solver.check()
```

All environments must be `unsat` for the checker to return `True`. One
Cedar-verified counterexample is sufficient to return `False`.

## Validation

The included suite contains **42 end-to-end tests plus 225 differential
expression cases** (43 unittest test methods in total). It checks direction,
all request environments, permit/forbid combination, optional data, absent
entities, aliasing, hierarchy properties, schema action domains, integer
overflow, Unicode/escape handling, sets, unsupported features, and solver
failure handling. Differential cases compare both expression truth and
error/no-error behavior with the actual Cedar evaluator. Every failing
implication returned by integration tests is independently replayed with Cedar.

## Source files

- `cedar_z3/checker.py`: public API and authorization combination.
- `cedar_z3/schema.py`: supported schema normalization and action environments.
- `cedar_z3/expressions.py`: Cedar PST-to-Z3 expression translation.
- `cedar_z3/environment.py`: symbolic requests, attributes, and hierarchy.
- `cedar_z3/model.py`: typed intermediate values, equality, and conditionals.
- `cedar_z3/counterexample.py`: finite model materialization and Unicode decoding.
- `tests/`: executable differential and integration tests.

## References

- [Cedar authorization semantics](https://docs.cedarpolicy.com/auth/authorization.html)
- [Cedar operators](https://docs.cedarpolicy.com/policies/syntax-operators.html)
- [Cedar JSON schemas](https://docs.cedarpolicy.com/schema/json-schema.html)
- [cedar-py implementation and API](https://github.com/k9securityio/cedar-py)
- [Z3 Python API](https://z3prover.github.io/api/html/namespacez3py.html)

Cedar's symbolic compiler was consulted as a semantic reference; it is not
imported, invoked, installed by, or included in this package.
