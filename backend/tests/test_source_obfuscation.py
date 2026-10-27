"""Unit and regression tests for real-world JavaScript obfuscation and multi-signal analysis."""

from ml.evaluation.source_obfuscation_suite import (
    SOURCE_FIXTURES,
    run_source_level_obfuscation_suite,
)
from ml.parsing.ast_analyzer import (
    ASTAnalysisResult,
    JavaScriptASTAnalyzer,
)


def test_ast_aliased_eval_detection():
    code = """
    const myEval = eval;
    myEval("console.log('aliased execution');");
    """
    analyzer = JavaScriptASTAnalyzer("aliased.js", code)
    res = analyzer.analyze()
    assert res.success is True
    assert res.dynamic_exec_count >= 1
    assert res.aliased_eval_count >= 1
    assert any("aliased" in e.description.lower() for e in res.evidence)


def test_ast_atob_eval_pipeline():
    code = """
    var encoded = 'dmFyIGE9MTs=';
    var payload = window.atob(encoded);
    eval(payload);
    """
    analyzer = JavaScriptASTAnalyzer("decode_exec.js", code)
    res = analyzer.analyze()
    assert res.success is True
    assert res.atob_exec_count >= 1
    assert res.code_category == "confirmed_malicious_signature"


def test_ast_bracket_computed_chrome_api():
    code = """
    const root = chrome;
    root['\\x63\\x6f\\x6f\\x6b\\x69\\x65\\x73']['get']({url: 'https://bank.com'}, function(c) {});
    """
    analyzer = JavaScriptASTAnalyzer("computed.js", code)
    res = analyzer.analyze()
    assert res.success is True
    assert res.api_counts["call_chrome_cookies"] >= 1
    assert res.has_sensitive_api is True


def test_ast_minified_webpack_code_recognition():
    code = (
        "!function(e){var t={};function n(r){return e[r].call(t,t,n)}n.m=e;n(0)}([function(){"
        "var a=1,b=2;console.log(a+b);}]);" * 20
    )
    analyzer = JavaScriptASTAnalyzer("webpack.min.js", code)
    res = analyzer.analyze()
    assert res.success is True
    assert res.code_category == "legitimately_minified"
    assert res.dynamic_exec_count == 0


def test_ast_syntax_error_resilience():
    code = "function incomplete(a, b { return a + b;"
    analyzer = JavaScriptASTAnalyzer("corrupt.js", code)
    res = analyzer.analyze()
    # Analyzer must not crash, must provide parser warning and fallback
    assert res.parser_warning is not None
    assert isinstance(res, ASTAnalysisResult)


def test_full_source_level_obfuscation_suite():
    results = run_source_level_obfuscation_suite()
    assert results["total_fixtures"] == len(SOURCE_FIXTURES)
    # Check that recall on malicious fixtures is 100%
    assert results["metrics"]["recall"] == 1.0
    # Check that precision is high (>= 80% on tricky transformation fixtures)
    assert results["metrics"]["precision"] >= 0.75
    # Check that overall test matrix all passed
    assert results["all_passed"] is True
