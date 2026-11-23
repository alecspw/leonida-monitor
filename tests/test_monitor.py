import unittest
import monitor


class ScanDiffTests(unittest.TestCase):
    def test_flags_added_dangerous_line(self):
        diff = """diff --git a/src/a.py b/src/a.py
--- a/src/a.py
+++ b/src/a.py
@@ -1,1 +1,1 @@
-os.system(\"old\")
+os.system(\"new\")
"""
        findings = monitor.scan_diff(diff, [])
        self.assertTrue(any(f["pattern"] == "Direct OS command execution" and f["line"] == 1 for f in findings))

    def test_ignores_removed_lines(self):
        diff = """diff --git a/src/a.py b/src/a.py
--- a/src/a.py
+++ b/src/a.py
@@ -1,1 +0,0 @@
-os.system(\"removed\")
"""
        self.assertEqual(monitor.scan_diff(diff, []), [])

    def test_ignores_context_lines(self):
        diff = """diff --git a/src/a.py b/src/a.py
--- a/src/a.py
+++ b/src/a.py
@@ -1,1 +1,1 @@
 os.system(\"unchanged\")
+print(\"safe\")
"""
        self.assertEqual(monitor.scan_diff(diff, []), [])


if __name__ == "__main__":
    unittest.main()
