"""Structural JavaScript AST Analyzer for Sentinel Extension Detector.

Provides pure zero-execution static analysis of JavaScript source code using
Esprima AST parsing and lexical fallback:
- Direct and indirect dynamic code execution (eval, Function constructor)
- Variable aliasing for sensitive functions (e.g. const e = eval; e(...))
- Decode-to-execution pipelines (atob -> eval)
- String-array extraction and rotation loops (Obfuscator.io patterns)
- Computed and hex-encoded member access (e.g. chrome['\\x63\\x6f\\x6f\\x6b\\x69\\x65\\x73'])
- Sensitive Chromium extension APIs (chrome.* and browser.*)
- Dynamic DOM script creation and injection
- Network egress and endpoint construction
- Multi-signal code classification:
  1. ordinary_source
  2. legitimately_minified
  3. suspiciously_transformed
  4. obfuscated_with_sensitive_behavior
  5. confirmed_malicious_signature
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import esprima
    HAS_ESPRIMA = True
except ImportError:
    esprima = None  # type: ignore
    HAS_ESPRIMA = False


HEX_IDENTIFIER_PATTERN = re.compile(r"^_0x[a-fA-F0-9]{3,8}$")
SENSITIVE_APIS = {
    "cookies": "call_chrome_cookies",
    "webrequest": "call_chrome_webrequest",
    "tabs": "call_chrome_tabs",
    "history": "call_chrome_history",
    "storage": "call_chrome_storage",
    "scripting": "call_chrome_scripting",
    "declarativenetrequest": "call_chrome_declarativenetrequest",
    "management": "call_chrome_management",
    "proxy": "call_chrome_proxy",
    "downloads": "call_chrome_downloads",
}

NETWORK_CALLS = {
    "fetch": "call_fetch",
    "xmlhttprequest": "call_xmlhttprequest",
    "websocket": "call_websocket",
    "sendbeacon": "call_sendbeacon",
}


@dataclass
class FindingEvidence:
    category: str  # "observed_fact", "heuristic_suspicion", "threat_indicator"
    description: str
    file_name: str
    line_number: int | None = None
    node_type: str | None = None


@dataclass
class ASTAnalysisResult:
    file_name: str
    success: bool
    parser_warning: str | None = None
    api_counts: dict[str, int] = field(default_factory=dict)
    dynamic_exec_count: int = 0
    aliased_eval_count: int = 0
    atob_exec_count: int = 0
    string_array_rotations: int = 0
    hex_identifiers: int = 0
    computed_hex_properties: int = 0
    dom_script_injections: int = 0
    network_call_count: int = 0
    dynamic_url_constructions: int = 0
    has_sensitive_api: bool = False
    has_network_egress: bool = False
    sensitive_data_exfiltration_risk: bool = False
    code_category: str = "ordinary_source"
    evidence: list[FindingEvidence] = field(default_factory=list)


def decode_hex_escapes(raw_str: str) -> str:
    """Safely decode hex escape sequences like \\x63\\x6f\\x6f\\x6b\\x69\\x65\\x73 into text."""
    if not isinstance(raw_str, str):
        return ""
    try:
        # Replace \\xNN sequences
        def _replace_hex(match: re.Match) -> str:
            hex_val = match.group(1)
            try:
                return chr(int(hex_val, 16))
            except Exception:
                return match.group(0)

        return re.sub(r"\\x([0-9a-fA-F]{2})", _replace_hex, raw_str)
    except Exception:
        return raw_str


class JavaScriptASTAnalyzer:
    """Zero-execution static AST visitor and multi-signal JavaScript classifier."""

    def __init__(self, filename: str, source_text: str):
        self.filename = filename
        self.source_text = source_text
        self.lines = source_text.splitlines()
        self.total_lines = len(self.lines)
        self.total_chars = len(source_text)

        # Aliasing tracking: identifier -> resolved target ('eval', 'Function', 'atob', etc.)
        self.aliases: dict[str, str] = {}
        # Track string arrays: array name -> True
        self.string_arrays: set[str] = set()
        # Track variables holding decoded atob values: var_name -> True
        self.atob_vars: set[str] = set()

        # Metrics collected
        self.api_counts: dict[str, int] = {v: 0 for v in SENSITIVE_APIS.values()}
        for net_v in NETWORK_CALLS.values():
            self.api_counts[net_v] = 0

        self.dynamic_exec_count = 0
        self.aliased_eval_count = 0
        self.atob_exec_count = 0
        self.string_array_rotations = 0
        self.hex_identifiers = set()
        self.computed_hex_properties = 0
        self.dom_script_injections = 0
        self.network_call_count = 0
        self.dynamic_url_constructions = 0
        self.evidence: list[FindingEvidence] = []
        self.parser_warning: str | None = None

    def analyze(self) -> ASTAnalysisResult:
        """Execute structural static AST analysis with automatic fallback."""
        if not HAS_ESPRIMA or not self.source_text.strip():
            # Fall back to lexical analysis
            return self._lexical_fallback()

        ast = None
        try:
            # Try script parsing first
            ast = esprima.parseScript(self.source_text, loc=True, tolerant=True)
        except Exception:
            try:
                # Try module parsing (ES6 modules with import/export)
                ast = esprima.parseModule(self.source_text, loc=True, tolerant=True)
            except Exception as e:
                self.parser_warning = f"ES-AST parsing tolerance fallback in {self.filename}: {type(e).__name__}"

        if ast is None:
            return self._lexical_fallback(warning=self.parser_warning)

        # Walk AST recursively
        self._traverse(ast)

        # Post-analysis synthesis
        self.has_sensitive_api = any(
            self.api_counts[k] > 0
            for k in ["call_chrome_cookies", "call_chrome_tabs", "call_chrome_history", "call_chrome_storage"]
        )
        self.has_network_egress = any(
            self.api_counts[k] > 0
            for k in ["call_fetch", "call_xmlhttprequest", "call_websocket", "call_sendbeacon"]
        )
        self.sensitive_data_exfiltration_risk = bool(self.has_sensitive_api and self.has_network_egress)

        if self.sensitive_data_exfiltration_risk:
            self.evidence.append(
                FindingEvidence(
                    category="threat_indicator",
                    description="Structural correlation: sensitive browser data access co-occurring with outbound network calls in same script.",
                    file_name=self.filename,
                )
            )

        # Determine 5-category multi-signal code transformation classification
        code_category = self._classify_code_category()

        return ASTAnalysisResult(
            file_name=self.filename,
            success=True,
            parser_warning=self.parser_warning,
            api_counts=self.api_counts,
            dynamic_exec_count=self.dynamic_exec_count,
            aliased_eval_count=self.aliased_eval_count,
            atob_exec_count=self.atob_exec_count,
            string_array_rotations=self.string_array_rotations,
            hex_identifiers=len(self.hex_identifiers),
            computed_hex_properties=self.computed_hex_properties,
            dom_script_injections=self.dom_script_injections,
            network_call_count=self.network_call_count,
            dynamic_url_constructions=self.dynamic_url_constructions,
            has_sensitive_api=self.has_sensitive_api,
            has_network_egress=self.has_network_egress,
            sensitive_data_exfiltration_risk=self.sensitive_data_exfiltration_risk,
            code_category=code_category,
            evidence=self.evidence,
        )

    def _traverse(self, node: Any) -> None:
        """Recursive AST node visitor."""
        if node is None or not hasattr(node, "type"):
            return

        ntype = getattr(node, "type", "")
        loc = getattr(node, "loc", None)
        line = loc.start.line if loc and hasattr(loc, "start") else None

        # 1. Variable Declarations (inspect aliases & string arrays)
        if ntype == "VariableDeclarator":
            self._handle_variable_declarator(node, line)

        # 2. Assignment Expressions (inspect dynamic property assignments or aliasing)
        elif ntype == "AssignmentExpression":
            self._handle_assignment_expression(node, line)

        # 3. Call Expressions & New Expressions (eval, Function, chrome APIs, network, DOM)
        elif ntype in {"CallExpression", "NewExpression"}:
            self._handle_call_or_new(node, line)

        # 4. Member Expressions (chrome['cookies'], window['eval'])
        elif ntype == "MemberExpression":
            self._handle_member_expression(node, line)

        # 5. Binary Expressions (URL construction)
        elif ntype == "BinaryExpression":
            self._handle_binary_expression(node, line)

        # 6. Identifier inspection (hex variable naming)
        elif ntype == "Identifier":
            name = getattr(node, "name", "")
            if name and HEX_IDENTIFIER_PATTERN.match(name):
                self.hex_identifiers.add(name)

        # Recursively visit children
        for attr, val in vars(node).items():
            if attr in {"loc", "range", "type"}:
                continue
            if isinstance(val, list):
                for item in val:
                    if hasattr(item, "type"):
                        self._traverse(item)
            elif hasattr(val, "type"):
                self._traverse(val)

    def _handle_variable_declarator(self, node: Any, line: int | None) -> None:
        """Inspect var/let/const declarations for aliases, string arrays, and atob results."""
        ident = getattr(node, "id", None)
        init = getattr(node, "init", None)
        if not ident or getattr(ident, "type", "") != "Identifier" or not init:
            return

        var_name = getattr(ident, "name", "")
        init_type = getattr(init, "type", "")

        # Track hex identifier
        if HEX_IDENTIFIER_PATTERN.match(var_name):
            self.hex_identifiers.add(var_name)

        # Detect string arrays (e.g. var _0x1234 = ['foo', 'bar', 'baz', 'qux'])
        if init_type == "ArrayExpression":
            elements = getattr(init, "elements", [])
            if len(elements) >= 4 and all(
                getattr(e, "type", "") == "Literal" and isinstance(getattr(e, "value", None), str)
                for e in elements if e is not None
            ):
                self.string_arrays.add(var_name)

        # Detect eval or Function or chrome aliasing: const _e = eval; or const c = chrome;
        if init_type == "Identifier":
            target = getattr(init, "name", "")
            if target in {"eval", "Function", "atob", "btoa", "chrome", "browser"}:
                self.aliases[var_name] = target
                if target in {"eval", "Function"}:
                    self.aliased_eval_count += 1
                self.evidence.append(
                    FindingEvidence(
                        category="heuristic_suspicion",
                        description=f"Aliased function/object: '{var_name}' assigned from '{target}'.",
                        file_name=self.filename,
                        line_number=line,
                        node_type="VariableDeclarator",
                    )
                )

        # Detect member-assigned eval: var e = window['eval']; or window.eval
        elif init_type == "MemberExpression":
            obj_name = self._get_root_identifier(getattr(init, "object", None))
            prop_name = self._get_member_prop_name(init)
            if prop_name in {"eval", "Function", "atob", "btoa"}:
                self.aliases[var_name] = prop_name
                if prop_name in {"eval", "Function"}:
                    self.aliased_eval_count += 1
                self.evidence.append(
                    FindingEvidence(
                        category="heuristic_suspicion",
                        description=f"Dynamic evaluation aliased from '{obj_name}.{prop_name}' into '{var_name}'.",
                        file_name=self.filename,
                        line_number=line,
                        node_type="MemberExpression",
                    )
                )

        # Detect atob decode assignment: const decoded = atob(...); or window.atob(...)
        elif init_type == "CallExpression":
            callee_name = self._get_callee_name(getattr(init, "callee", None))
            if callee_name in {"atob", "window.atob", "globalThis.atob"} or callee_name.endswith(".atob") or self.aliases.get(callee_name) == "atob":
                self.atob_vars.add(var_name)

    def _handle_assignment_expression(self, node: Any, line: int | None) -> None:
        """Inspect assignments for script injection (script.src = ...) and aliasing."""
        left = getattr(node, "left", None)
        right = getattr(node, "right", None)
        if not left or not right:
            return

        # Check script.src assignment
        if getattr(left, "type", "") == "MemberExpression":
            prop_name = self._get_member_prop_name(left)
            if prop_name == "src":
                # Check if assigning a remote URL
                if getattr(right, "type", "") == "Literal":
                    val = str(getattr(right, "value", ""))
                    if val.startswith(("http://", "https://", "//")):
                        self.dom_script_injections += 1
                        self.evidence.append(
                            FindingEvidence(
                                category="threat_indicator",
                                description=f"DOM script injection targeting remote URL: {val[:60]}",
                                file_name=self.filename,
                                line_number=line,
                                node_type="AssignmentExpression",
                            )
                        )

    def _handle_call_or_new(self, node: Any, line: int | None) -> None:
        """Inspect function and constructor calls."""
        callee = getattr(node, "callee", None)
        if not callee:
            return

        callee_name = self._get_callee_name(callee)
        args = getattr(node, "arguments", [])

        # 1. Check eval() or aliased eval
        if callee_name == "eval" or self.aliases.get(callee_name) == "eval":
            self.dynamic_exec_count += 1
            if callee_name != "eval" and self.aliases.get(callee_name) == "eval":
                self.aliased_eval_count += 1
            # Check for atob pipe: eval(atob(...)) or eval(decoded_var)
            if args:
                first_arg = args[0]
                arg_callee = self._get_callee_name(getattr(first_arg, "callee", None)) if getattr(first_arg, "type", "") == "CallExpression" else ""
                arg_ident = getattr(first_arg, "name", "") if getattr(first_arg, "type", "") == "Identifier" else ""

                if arg_callee in {"atob", "window.atob", "globalThis.atob"} or arg_callee.endswith(".atob") or arg_ident in self.atob_vars:
                    self.atob_exec_count += 1
                    self.evidence.append(
                        FindingEvidence(
                            category="threat_indicator",
                            description="Direct decode-to-execution pipeline: atob() payload passed into eval().",
                            file_name=self.filename,
                            line_number=line,
                            node_type="CallExpression",
                        )
                    )
                elif callee_name != "eval":
                    self.evidence.append(
                        FindingEvidence(
                            category="heuristic_suspicion",
                            description=f"Aliased dynamic code evaluation via {callee_name}() (aliased from eval).",
                            file_name=self.filename,
                            line_number=line,
                            node_type="CallExpression",
                        )
                    )
                else:
                    self.evidence.append(
                        FindingEvidence(
                            category="heuristic_suspicion",
                            description="Direct dynamic code evaluation via eval().",
                            file_name=self.filename,
                            line_number=line,
                            node_type="CallExpression",
                        )
                    )

        # 2. Check Function constructor: new Function(...) or Function(...)
        elif callee_name == "Function" or self.aliases.get(callee_name) == "Function":
            self.dynamic_exec_count += 1
            if args and any(
                (getattr(a, "type", "") == "Identifier" and getattr(a, "name", "") in self.atob_vars)
                or (getattr(a, "type", "") == "CallExpression" and self._get_callee_name(getattr(a, "callee", None)) == "atob")
                for a in args
            ):
                self.atob_exec_count += 1
                self.evidence.append(
                    FindingEvidence(
                        category="threat_indicator",
                        description="Decode-to-execution pipeline: atob() payload passed into Function constructor.",
                        file_name=self.filename,
                        line_number=line,
                        node_type="NewExpression",
                    )
                )
            else:
                self.evidence.append(
                    FindingEvidence(
                        category="heuristic_suspicion",
                        description="Dynamic code construction via Function() constructor.",
                        file_name=self.filename,
                        line_number=line,
                        node_type="NewExpression",
                    )
                )

        # 3. Check document.createElement('script')
        elif callee_name in {"document.createElement", "createElement"}:
            if args and getattr(args[0], "type", "") == "Literal":
                val = str(getattr(args[0], "value", "")).lower()
                if val == "script":
                    self.dom_script_injections += 1
                    self.evidence.append(
                        FindingEvidence(
                            category="observed_fact",
                            description="Dynamic DOM element creation: <script> tag.",
                            file_name=self.filename,
                            line_number=line,
                            node_type="CallExpression",
                        )
                    )

        # 4. Check network calls: fetch, XMLHttpRequest, WebSocket, sendBeacon
        callee_lower = callee_name.lower()
        if "fetch" in callee_lower:
            self.api_counts["call_fetch"] += 1
            self.network_call_count += 1
        elif "xmlhttprequest" in callee_lower:
            self.api_counts["call_xmlhttprequest"] += 1
            self.network_call_count += 1
        elif "websocket" in callee_lower:
            self.api_counts["call_websocket"] += 1
            self.network_call_count += 1
        elif "sendbeacon" in callee_lower:
            self.api_counts["call_sendbeacon"] += 1
            self.network_call_count += 1

        # 5. Check string array rotation loops (e.g. self-invoking function rotating array)
        if getattr(callee, "type", "") == "MemberExpression":
            prop = self._get_member_prop_name(callee)
            obj = getattr(callee, "object", None)
            obj_ident = getattr(obj, "name", "") if obj and getattr(obj, "type", "") == "Identifier" else ""
            if prop in {"push", "shift"} and (obj_ident in self.string_arrays or HEX_IDENTIFIER_PATTERN.match(obj_ident)):
                self.string_array_rotations += 1

    def _handle_member_expression(self, node: Any, line: int | None) -> None:
        """Inspect member expressions for sensitive Chrome APIs and computed hex access."""
        prop_name = self._get_member_prop_name(node)
        raw_obj = getattr(node, "object", None)
        root_name = self._get_root_identifier(raw_obj)

        # Check computed property with hex string: obj['\x63\x6f\x6f\x6b\x69\x65\x73']
        if getattr(node, "computed", False):
            prop_node = getattr(node, "property", None)
            if prop_node and getattr(prop_node, "type", "") == "Literal":
                val = str(getattr(prop_node, "value", ""))
                raw = str(getattr(prop_node, "raw", val))
                if "\\x" in raw or "\\u" in raw:
                    self.computed_hex_properties += 1
                prop_name = val

        # Map Chromium extension APIs: chrome.<api> or browser.<api>
        resolved_root = self.aliases.get(root_name, root_name)
        if resolved_root in {"chrome", "browser"}:
            api_key = prop_name.lower()
            if api_key in SENSITIVE_APIS:
                feat_key = SENSITIVE_APIS[api_key]
                self.api_counts[feat_key] += 1
                self.evidence.append(
                    FindingEvidence(
                        category="observed_fact",
                        description=f"Extension API invocation: {resolved_root}.{prop_name}",
                        file_name=self.filename,
                        line_number=line,
                        node_type="MemberExpression",
                    )
                )

    def _handle_binary_expression(self, node: Any, line: int | None) -> None:
        """Inspect string concatenations for dynamically constructed URLs."""
        op = getattr(node, "operator", "")
        if op != "+":
            return
        left = getattr(node, "left", None)
        right = getattr(node, "right", None)

        left_val = getattr(left, "value", "") if getattr(left, "type", "") == "Literal" else ""
        right_val = getattr(right, "value", "") if getattr(right, "type", "") == "Literal" else ""

        if isinstance(left_val, str) and isinstance(right_val, str):
            combined = (left_val + right_val).strip().lower()
            if combined.startswith(("http://", "https://", "ws://", "wss://")) and len(combined) > 8:
                self.dynamic_url_constructions += 1

    def _classify_code_category(self) -> str:
        """Multi-signal classification distinguishing ordinary, minified, transformed, and obfuscated code."""
        # 1. Confirmed malicious signature: decode-to-exec OR exfiltration pipeline with dynamic code
        if self.atob_exec_count > 0 or (self.sensitive_data_exfiltration_risk and self.dynamic_exec_count > 0):
            return "confirmed_malicious_signature"

        # 2. Obfuscated with sensitive behavior: rotation loops or heavy hex identifiers WITH browser APIs or network calls
        has_obfuscation_patterns = (self.string_array_rotations > 0 or len(self.hex_identifiers) >= 10)
        has_security_relevance = (self.has_sensitive_api or self.has_network_egress or self.dom_script_injections > 0)
        if has_obfuscation_patterns and has_security_relevance:
            return "obfuscated_with_sensitive_behavior"

        # 3. Suspiciously transformed: hex identifiers or rotations present, but without verified sensitive APIs
        if has_obfuscation_patterns:
            return "suspiciously_transformed"

        # 4. Legitimately minified: long lines, minified formatting, but NO rotation loops and low hex density
        avg_line_len = (self.total_chars / self.total_lines) if self.total_lines > 0 else 0
        is_minified_structure = (self.total_lines <= 20 and self.total_chars > 3000) or avg_line_len > 200
        if is_minified_structure and len(self.hex_identifiers) < 5 and self.string_array_rotations == 0:
            return "legitimately_minified"

        # 5. Ordinary source
        return "ordinary_source"

    def _get_callee_name(self, node: Any) -> str:
        """Return representation of a function callee."""
        if not node:
            return ""
        ntype = getattr(node, "type", "")
        if ntype == "Identifier":
            return getattr(node, "name", "")
        elif ntype == "MemberExpression":
            obj_name = self._get_root_identifier(getattr(node, "object", None))
            prop_name = self._get_member_prop_name(node)
            return f"{obj_name}.{prop_name}" if obj_name else prop_name
        return ""

    def _get_root_identifier(self, node: Any) -> str:
        """Trace object tree down to the root identifier."""
        if not node:
            return ""
        ntype = getattr(node, "type", "")
        if ntype == "Identifier":
            return getattr(node, "name", "")
        elif ntype == "MemberExpression":
            return self._get_root_identifier(getattr(node, "object", None))
        elif ntype == "ThisExpression":
            return "this"
        return ""

    def _get_member_prop_name(self, node: Any) -> str:
        """Extract property name from MemberExpression."""
        if not node or getattr(node, "type", "") != "MemberExpression":
            return ""
        prop = getattr(node, "property", None)
        if not prop:
            return ""
        if getattr(node, "computed", False):
            if getattr(prop, "type", "") == "Literal":
                return str(getattr(prop, "value", ""))
            elif getattr(prop, "type", "") == "Identifier":
                return getattr(prop, "name", "")
        else:
            return getattr(prop, "name", "")
        return ""

    def _lexical_fallback(self, warning: str | None = None) -> ASTAnalysisResult:
        """Safe zero-execution lexical fallback when AST parsing cannot be completed."""
        evidence: list[FindingEvidence] = []
        if warning:
            evidence.append(
                FindingEvidence(
                    category="heuristic_suspicion",
                    description=warning,
                    file_name=self.filename,
                )
            )

        api_counts = {v: 0 for v in SENSITIVE_APIS.values()}
        for net_v in NETWORK_CALLS.values():
            api_counts[net_v] = 0

        # Regex fallback for sensitive APIs
        for api_name, feat_key in SENSITIVE_APIS.items():
            pattern = re.compile(rf"\b(?:chrome|browser)\.{api_name}\b", re.IGNORECASE)
            matches = len(pattern.findall(self.source_text))
            api_counts[feat_key] = matches

        # Regex fallback for network calls
        for net_name, feat_key in NETWORK_CALLS.items():
            pattern = re.compile(rf"\b{net_name}\b", re.IGNORECASE)
            matches = len(pattern.findall(self.source_text))
            api_counts[feat_key] = matches

        # Dynamic eval
        eval_matches = len(re.findall(r"\beval\s*\(", self.source_text))
        func_matches = len(re.findall(r"\bnew\s+Function\s*\(", self.source_text))
        dynamic_exec = eval_matches + func_matches

        # Hex identifiers
        hex_ids = len(re.findall(r"\b_0x[a-fA-F0-9]{3,8}\b", self.source_text))

        # atob to eval
        atob_eval = len(re.findall(r"(?:eval|Function)\s*\(\s*(?:window\.)?atob", self.source_text))

        has_sensitive = any(api_counts[k] > 0 for k in ["call_chrome_cookies", "call_chrome_tabs"])
        has_network = any(api_counts[k] > 0 for k in ["call_fetch", "call_xmlhttprequest"])

        # Determine fallback category
        avg_len = (self.total_chars / self.total_lines) if self.total_lines > 0 else 0
        if atob_eval > 0:
            category = "confirmed_malicious_signature"
        elif hex_ids >= 10 and (has_sensitive or has_network):
            category = "obfuscated_with_sensitive_behavior"
        elif hex_ids >= 10:
            category = "suspiciously_transformed"
        elif avg_len > 200 and hex_ids == 0:
            category = "legitimately_minified"
        else:
            category = "ordinary_source"

        return ASTAnalysisResult(
            file_name=self.filename,
            success=False,
            parser_warning=warning or "Lexical scanner fallback executed",
            api_counts=api_counts,
            dynamic_exec_count=dynamic_exec,
            aliased_eval_count=0,
            atob_exec_count=atob_eval,
            string_array_rotations=0,
            hex_identifiers=hex_ids,
            computed_hex_properties=0,
            dom_script_injections=0,
            network_call_count=sum(api_counts[k] for k in NETWORK_CALLS.values()),
            dynamic_url_constructions=0,
            has_sensitive_api=has_sensitive,
            has_network_egress=has_network,
            sensitive_data_exfiltration_risk=bool(has_sensitive and has_network),
            code_category=category,
            evidence=evidence,
        )


def analyze_javascript_file(file_path: Path) -> ASTAnalysisResult:
    """Analyze a single JavaScript source file strictly without code execution."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        return ASTAnalysisResult(
            file_name=file_path.name,
            success=False,
            parser_warning=f"File read error: {e}",
            code_category="ordinary_source",
        )

    analyzer = JavaScriptASTAnalyzer(filename=file_path.name, source_text=content)
    return analyzer.analyze()
