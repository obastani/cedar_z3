"""Cedar `like` differential checks and verified implication witnesses."""

import json
import unittest

import cedarpy
import z3

from cedar_z3 import check_implication
from cedar_z3.expressions import ExpressionCompiler
from cedar_z3.model import (
    BOOL, STRING, Field, Type, Value, encoded_string_regex, string_literal,
)


class ConcreteStringEnvironment:
    """Concrete valid strings; Cedar itself supplies the expected semantics."""

    def __init__(self, text, present=True, flag=False):
        self.constraints = []
        self.variables = {
            "context": Value(
                Type("record"),
                {
                    "text": Field(z3.BoolVal(present), Value(STRING, string_literal(text))),
                    "flag": Field(z3.BoolVal(True), Value(BOOL, z3.BoolVal(flag))),
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
            raise AssertionError("These differential cases use one attribute")
        return Value(BOOL, base.data[names[0]].present, base.ok)


def parse_expression(expression):
    source = f"permit(principal, action, resource) when {{ {expression} }};"
    policies = cedarpy.PolicySet.from_str(source)
    node = policies.to_pst().static_policies["policy0"].clauses[0].expr
    return policies, node


def request(context):
    return {
        "principal": {"type": "Agent", "id": "agent"},
        "action": {"type": "Action", "id": "ReadExecute"},
        "resource": {"type": "File", "id": "file"},
        "context": context,
    }


class LikeDifferentialTests(unittest.TestCase):
    def compare(self, policies, node, text, *, present=True, flag=False):
        context = {"flag": flag}
        if present:
            context["text"] = text
        actual = cedarpy.is_authorized(request(context), policies, [])
        env = ConcreteStringEnvironment(text, present, flag)
        encoded = ExpressionCompiler(env).compile(node)
        solver = z3.Solver()
        solver.set(timeout=3_000)
        solver.add(*env.constraints)
        solver.add(z3.Or(
            z3.And(encoded.ok, encoded.data) != z3.BoolVal(actual.allowed),
            encoded.ok != z3.BoolVal(not bool(actual.diagnostics.errors)),
        ))
        self.assertEqual(solver.check(), z3.unsat)
        return actual

    def test_wildcards_and_literal_metacharacters_against_cedar(self):
        # These strings are Cedar source patterns, including their delimiters.
        patterns = (
            '""', '"*"', '"**"', '"abc"', '"a*b"', '"*ab*"', '"a***b"',
            '"?."', '"[ab]"', '"a|b"', '"a+b"', '"a(b)"', '"^a$"',
            r'"a\*b"', r'"\*"', r'"\\*"', r'"\\\*"', r'"*\\\**"',
        )
        values = (
            "", "a", "b", "ab", "abc", "xabc", "abcx", "axb", "a/b",
            "a\nb", "a*b", "*", "**", "?.", "?x", "[ab]", "a|b", "a+b",
            "a(b)", "^a$", "\\", "\\*", "\\abc", "a\\*b", "🐱", "é",
        )
        for pattern in patterns:
            policies, node = parse_expression(f"context.text like {pattern}")
            for value in values:
                with self.subTest(pattern=pattern, value=value):
                    self.compare(policies, node, value)

    def test_unicode_and_control_characters_against_cedar(self):
        patterns = (
            '"é*"', '"🐱*"', r'"\u{30000}*"', r'"\u{10ffff}*"',
            r'"\u{0}*"', r'"\n*\t"', r'"\\u{61}*"', '"*"', '"a*b"',
        )
        values = (
            "", "é", "éclair", "e\u0301", "🐱", "🐱cat", "cat🐱",
            "\U00030000", "\U00030000x", "\U0010ffff", "\U0010ffffx",
            "\x00", "\x00x", "\n\t", "\n🐱\t", "\na\r\nb\t",
            r"\u{61}", r"\u{61}xyz", "a\x00b", "a\nb", "a🐱b",
        )
        for pattern in patterns:
            policies, node = parse_expression(f"context.text like {pattern}")
            for value in values:
                with self.subTest(pattern=pattern, value=value):
                    self.compare(policies, node, value)

    def test_explicit_zero_many_and_whole_string_examples(self):
        cases = (
            ('"a*b"', "ab", True),
            ('"a*b"', "a/many\ncharacters/b", True),
            ('"a*b"', "xa/many/b", False),
            ('"a*b"', "a/many/bx", False),
            ('"abc"', "abc", True),
            ('"abc"', "xabcx", False),
            ('""', "", True),
            ('""', "x", False),
            ('"**"', "", True),
            (r'"a\*b"', "a*b", True),
            (r'"a\*b"', "axxb", False),
            (r'"\\*"', "\\arbitrary", True),
            (r'"\\\*"', "\\arbitrary", False),
            (r'"\\\*"', "\\*", True),
            ('"?."', "?.", True),
            ('"?."', "ab", False),
        )
        for pattern, value, expected in cases:
            with self.subTest(pattern=pattern, value=value):
                policies, node = parse_expression(f"context.text like {pattern}")
                actual = self.compare(policies, node, value)
                self.assertEqual(actual.allowed, expected)

    def test_missing_attribute_errors_and_short_circuit_against_cedar(self):
        expressions = (
            'context.text like "a*"',
            '!(context.text like "a*")',
            'context has text && context.text like "a*"',
            '!(context has text) || context.text like "a*"',
            'context.flag || context.text like "a*"',
            'context.flag && context.text like "a*"',
            'if context.flag then true else context.text like "a*"',
            'if context has text then context.text like "a*" else true',
        )
        for expression in expressions:
            policies, node = parse_expression(expression)
            for value in ("", "apple", "banana"):
                for present in (False, True):
                    for flag in (False, True):
                        with self.subTest(expression=expression, value=value, present=present, flag=flag):
                            self.compare(policies, node, value, present=present, flag=flag)


class EncodedStringDomainTests(unittest.TestCase):
    def test_domain_matches_strict_utf8_at_encoding_boundaries(self):
        # Legal boundary scalars plus nearby overlong, surrogate, out-of-range,
        # misplaced continuation, and truncated byte sequences.
        byte_sequences = (
            b"", b"\x00", b"\x7f", b"\xc2\x80", b"\xdf\xbf",
            b"\xe0\xa0\x80", b"\xed\x9f\xbf", b"\xee\x80\x80",
            b"\xef\xbf\xbf", b"\xf0\x90\x80\x80", b"\xf3\xbf\xbf\xbf",
            b"\xf4\x8f\xbf\xbf", "a🐱\x00é".encode("utf-8"),
            b"\x80", b"\xbf", b"\xc0\x80", b"\xc1\xbf", b"\xc2\x7f",
            b"\xc2\xc0", b"\xe0\x9f\xbf", b"\xe1\x80\x7f",
            b"\xed\xa0\x80", b"\xed\xbf\xbf", b"\xf0\x8f\xbf\xbf",
            b"\xf4\x90\x80\x80", b"\xf5\x80\x80\x80", b"\xff",
            b"\xc2", b"\xe1\x80", b"\xf0\x90\x80", b"a\xe1\x80",
        )
        cases = []
        for value in byte_sequences:
            try:
                value.decode("utf-8", errors="strict")
                expected = True
            except UnicodeDecodeError:
                expected = False
            cases.append(("u" + value.hex(), expected))
        cases.extend((value, False) for value in (
            "", "61", "v61", "u0", "u0g", "uC280", "u616", "u ",
        ))
        for encoded, expected in cases:
            with self.subTest(encoded=encoded, expected=expected):
                solver = z3.Solver()
                solver.set(timeout=3_000)
                solver.add(z3.InRe(z3.StringVal(encoded), encoded_string_regex()) != expected)
                self.assertEqual(solver.check(), z3.unsat)


def schema():
    return {
        "": {
            "entityTypes": {
                "Agent": {},
                "File": {
                    "shape": {"type": "Record", "attributes": {"path": {"type": "String"}}}
                },
            },
            "actions": {
                "ReadExecute": {
                    "appliesTo": {
                        "principalTypes": ["Agent"],
                        "resourceTypes": ["File"],
                        "context": {
                            "type": "Record",
                            "attributes": {
                                "text": {"type": "String"},
                                "flag": {"type": "Boolean"},
                                "maybe": {"type": "String", "required": False},
                                "values": {"type": "Set", "element": {"type": "String"}},
                            },
                        },
                    }
                }
            },
        }
    }


def permit(condition):
    return f"permit(principal, action, resource) when {{ {condition} }};"


class LikeImplicationTests(unittest.TestCase):
    def check(self, a, b, expected):
        s = schema()
        result = check_implication(a, b, s, timeout_ms=10_000)
        self.assertIs(result.holds, expected)
        if expected:
            self.assertIsNone(result.counterexample)
        else:
            witness = result.counterexample
            self.assertIsNotNone(witness)
            cs = cedarpy.Schema.from_json_str(json.dumps(s))
            entities = cedarpy.Entities.from_json_str(json.dumps(witness.entities), schema=cs)
            aa = cedarpy.is_authorized(witness.request, a, entities, schema=cs)
            bb = cedarpy.is_authorized(witness.request, b, entities, schema=cs)
            self.assertEqual(aa.decision, cedarpy.Decision.Allow)
            self.assertEqual(bb.decision, cedarpy.Decision.Deny)
        return result

    def test_nested_path_pattern_implies_parent_pattern(self):
        self.check(
            permit('resource.path like "/workspace/src/*"'),
            permit('resource.path like "/workspace/*"'),
            True,
        )

    def test_prefix_and_suffix_pattern_implication(self):
        self.check(
            permit('context.text like "api.*.example.com"'),
            permit('context.text like "*.example.com"'),
            True,
        )

    def test_broader_pattern_returns_replayable_counterexample(self):
        result = self.check(
            permit('context.text like "ab*"'),
            permit('context.text like "abc*"'),
            False,
        )
        text = result.counterexample.request["context"]["text"]
        self.assertTrue(text.startswith("ab"))
        self.assertFalse(text.startswith("abc"))

    def test_pattern_without_wildcards_equals_string_equality(self):
        a, b = permit('context.text like "abc"'), permit('context.text == "abc"')
        self.check(a, b, True)
        self.check(b, a, True)

    def test_escaped_star_is_literal(self):
        literal = permit(r'context.text like "a\*b"')
        self.check(literal, permit('context.text == "a*b"'), True)
        self.check(permit('context.text == "a*b"'), literal, True)
        self.check(permit('context.text like "a*b"'), literal, False)

    def test_empty_pattern_only_matches_empty_string(self):
        self.check(permit('context.text like ""'), permit('context.text == ""'), True)
        self.check(permit('context.text == ""'), permit('context.text like ""'), True)

    def test_consecutive_stars_do_not_change_language(self):
        a, b = permit('context.text like "a***b"'), permit('context.text like "a*b"')
        self.check(a, b, True)
        self.check(b, a, True)

    def test_wildcard_matches_every_required_context_string(self):
        self.check(permit("true"), permit('context.text like "*"'), True)
        self.check(permit('!(context.text like "*")'), "", True)

    def test_missing_entity_attribute_is_still_an_error(self):
        self.check(permit('!(resource.path like "*")'), "", True)
        self.check(permit('resource.path like "*"'), permit("resource has path"), True)
        self.check(permit("resource has path"), permit('resource.path like "*"'), True)
        self.check(permit("true"), permit('resource.path like "*"'), False)

    def test_optional_attribute_guard_and_short_circuit(self):
        self.check(
            permit('context has maybe && context.maybe like "ab*"'),
            permit('context has maybe && context.maybe like "a*"'),
            True,
        )
        self.check(permit("context.flag"), permit('context.flag || resource.path like "a*"'), True)

    def test_broader_forbid_is_more_conservative(self):
        baseline = permit("true")
        narrow = baseline + '''
        forbid(principal, action, resource)
        when { resource.path like "/workspace/private/*" };
        '''
        broad = baseline + '''
        forbid(principal, action, resource)
        when { resource.path like "/workspace/*" };
        '''
        self.check(broad, narrow, True)
        self.check(narrow, broad, False)

    def test_unless_and_forbid_preserve_operand_errors(self):
        unless = '''
        permit(principal, action, resource) unless { resource.path like "*" };
        '''
        self.check(unless, "", True)
        # Missing File entities make the forbid error and get skipped; they
        # must not turn its negated pattern into a successful prohibition.
        baseline = permit("true")
        restricted = baseline + '''
        forbid(principal, action, resource) unless { resource.path like "*" };
        '''
        self.check(baseline, restricted, True)
        self.check(restricted, baseline, True)

    def test_high_unicode_and_literal_backslash_survive_counterexamples(self):
        for text in ("\U0010ffffsuffix", "\U00030000suffix", "🐱cat", "\x00abc", r"\u{61}"):
            literal = json.dumps(text, ensure_ascii=False)
            # JSON uses \u0000 for NUL, whereas Cedar uses \u{0}.
            literal = literal.replace(r"\u0000", r"\u{0}")
            with self.subTest(text=text):
                result = self.check(
                    permit(f"context.text == {literal}"),
                    permit('context.text like "ordinary*"'),
                    False,
                )
                self.assertEqual(result.counterexample.request["context"]["text"], text)

    def test_pattern_and_set_membership_share_string_values(self):
        self.check(
            permit('context.values == ["abc"] && context.values.contains(context.text)'),
            permit('context.text like "a*"'),
            True,
        )
        result = self.check(
            permit('["abc", "xyz"].contains(context.text)'),
            permit('context.text like "a*"'),
            False,
        )
        self.assertEqual(result.counterexample.request["context"]["text"], "xyz")


if __name__ == "__main__":
    unittest.main()
